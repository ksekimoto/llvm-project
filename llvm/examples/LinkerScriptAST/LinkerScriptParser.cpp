#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include <cassert>
#include <limits>
#include <utility>
#include <vector>

using namespace llvm;
using namespace llvm::ELF;
using namespace llvm::support::endian;
using namespace llvm::sys;

//===----------------------------------------------------------------------===//
// Support
//===----------------------------------------------------------------------===//

unsigned eCount;
inline uint64_t errorCount() { return eCount; }

inline void error(const Twine &msg) {
  fprintf(stderr, "Error: %s\n", msg.str().c_str());
}

// These two classes are hack to keep track of all
// SpecificBumpPtrAllocator instances.
struct SpecificAllocBase {
  SpecificAllocBase() { instances.push_back(this); }
  virtual ~SpecificAllocBase() = default;
  virtual void reset() = 0;
  static std::vector<SpecificAllocBase *> instances;
};

template <class T> struct SpecificAlloc : public SpecificAllocBase {
  void reset() override { alloc.DestroyAll(); }
  llvm::SpecificBumpPtrAllocator<T> alloc;
};

std::vector<SpecificAllocBase *> SpecificAllocBase::instances;

// Use this arena if your object has a destructor.
// Your destructor will be invoked from freeArena().
template <typename T, typename... U> T *make(U &&... args) {
  static SpecificAlloc<T> alloc;
  return new (alloc.alloc.Allocate()) T(std::forward<U>(args)...);
}

Optional<MemoryBufferRef> readFile(StringRef path) {
  auto mbOrErr = MemoryBuffer::getFile(path, -1, false);
  if (auto ec = mbOrErr.getError()) {
    error("cannot open " + path + ": " + ec.message());
    return None;
  }

  std::unique_ptr<MemoryBuffer> &mb = *mbOrErr;
  MemoryBufferRef mbref = mb->getMemBufferRef();
  make<std::unique_ptr<MemoryBuffer>>(std::move(mb)); // take MB ownership

  // if (tar)
  //  tar->append(relativeToRoot(path), mbref.getBuffer());
  return mbref;
}

//===----------------------------------------------------------------------===//
// Abstract Syntax Tree
//===----------------------------------------------------------------------===//

class Expr {};

enum SectionsCommandKind {
  AssignmentKind, // . = expr or <sym> = expr
  OutputSectionKind,
  InputSectionKind,
  ByteKind // BYTE(expr), SHORT(expr), LONG(expr) or QUAD(expr)
};

struct BaseCommand {
  BaseCommand(int k) : kind(k) {}
  int kind;
};

// This represents ". = <expr>" or "<symbol> = <expr>".
struct SymbolAssignment : BaseCommand {
  SymbolAssignment(StringRef name, Expr e, std::string loc)
      : BaseCommand(AssignmentKind), name(name), expression(e), location(loc) {}

  static bool classof(const BaseCommand *c) {
    return c->kind == AssignmentKind;
  }

  // The LHS of an expression. Name is either a symbol name or ".".
  StringRef name;
  // Defined *sym = nullptr;

  // The RHS of an expression.
  Expr expression;

  // Command attributes for PROVIDE, HIDDEN and PROVIDE_HIDDEN.
  bool provide = false;
  bool hidden = false;

  // Holds file name and line number for error reporting.
  std::string location;

  // A string representation of this command. We use this for -Map.
  std::string commandString;

  // Address of this assignment command.
  unsigned addr;

  // Size of this assignment command. This is usually 0, but if
  // you move '.' this may be greater than 0.
  unsigned size;
};

// Represents BYTE(), SHORT(), LONG(), or QUAD().
struct ByteCommand : BaseCommand {
  ByteCommand(Expr e, unsigned size, std::string commandString)
      : BaseCommand(ByteKind), commandString(commandString), expression(e),
        size(size) {}

  static bool classof(const BaseCommand *c) { return c->kind == ByteKind; }

  // Keeps string representing the command. Used for -Map" is perhaps better.
  std::string commandString;

  Expr expression;

  // This is just an offset of this assignment command in the output section.
  unsigned offset;

  // Size of this data command.
  unsigned size;
};

struct PhdrsCommand {
  StringRef name;
  unsigned type = llvm::ELF::PT_NULL;
  bool hasFilehdr = false;
  bool hasPhdrs = false;
  Expr flags;
  Expr lmaExpr;
};

class StringMatcher {
public:
  StringMatcher() = default;
  explicit StringMatcher(StringRef pat);

  bool match(llvm::StringRef s) const;

private:
  std::vector<StringRef> patterns;
};

StringMatcher::StringMatcher(StringRef pat) {
  patterns.push_back(pat); // todo revisit
}

struct InputSectionDescription : BaseCommand {
  InputSectionDescription(StringRef filePattern)
      : BaseCommand(InputSectionKind), filePat(filePattern) {}

  static bool classof(const BaseCommand *c) {
    return c->kind == InputSectionKind;
  }

  StringMatcher filePat;
};

enum class SortSectionPolicy { Default, None, Alignment, Name, Priority };

// This struct represents one section match pattern in SECTIONS() command.
// It can optionally have negative match pattern for EXCLUDED_FILE command.
// Also it may be surrounded with SORT() command, so contains sorting rules.
struct SectionPattern {
  SectionPattern(StringMatcher &&pat1, StringMatcher &&pat2)
      : excludedFilePat(pat1), sectionPat(pat2),
        sortOuter(SortSectionPolicy::Default),
        sortInner(SortSectionPolicy::Default) {}

  StringMatcher excludedFilePat;
  StringMatcher sectionPat;
  SortSectionPolicy sortOuter;
  SortSectionPolicy sortInner;
};

// This struct is used to represent the location and size of regions of
// target memory. Instances of the struct are created by parsing the
// MEMORY command.
struct MemoryRegion {
  MemoryRegion(StringRef name, Expr origin, Expr length, uint32_t flags,
               uint32_t negFlags)
      : name(name), origin(origin), length(length), flags(flags),
        negFlags(negFlags) {}

  std::string name;
  Expr origin;
  Expr length;
  uint32_t flags;
  uint32_t negFlags;
  uint64_t curPos = 0;
};

class OutputSection;

class SectionBase {
public:
  enum Kind { Regular, EHFrame, Merge, Synthetic, Output };

  Kind kind() const { return (Kind)sectionKind; }

  StringRef name;

  // This pointer points to the "real" instance of this instance.
  // Usually Repl == this. However, if ICF merges two sections,
  // Repl pointer of one section points to another section. So,
  // if you need to get a pointer to this instance, do not use
  // this but instead this->Repl.
  SectionBase *repl;

  unsigned sectionKind : 3;

  // The next two bit fields are only used by InputSectionBase, but we
  // put them here so the struct packs better.

  unsigned bss : 1;

  // Set for sections that should not be folded by ICF.
  unsigned keepUnique : 1;

  // These corresponds to the fields in Elf_Shdr.
  uint32_t alignment;
  uint64_t flags;
  uint64_t entsize;
  uint32_t type;
  uint32_t link;
  uint32_t info;

  OutputSection *getOutputSection();
  const OutputSection *getOutputSection() const {
    return const_cast<SectionBase *>(this)->getOutputSection();
  }

  // Translate an offset in the input section to an offset in the output
  // section.
  uint64_t getOffset(uint64_t offset) const;

  uint64_t getVA(uint64_t offset = 0) const;

protected:
  SectionBase(Kind sectionKind, StringRef name, uint64_t flags,
              uint64_t entsize, uint64_t alignment, uint32_t type,
              uint32_t info, uint32_t link)
      : name(name), repl(this), sectionKind(sectionKind), bss(false),
        keepUnique(false), alignment(alignment), flags(flags), entsize(entsize),
        type(type), link(link), info(info) {}
};

// Linker scripts allow additional constraints to be put on output sections.
// If an output section is marked as ONLY_IF_RO, the section is created
// only if its input sections are read-only. Likewise, an output section
// with ONLY_IF_RW is created if all input sections are RW.
enum class ConstraintKind { NoConstraint, ReadOnly, ReadWrite };

class OutputSection final : public BaseCommand, public SectionBase {
public:
  OutputSection(StringRef name, uint32_t type, uint64_t flags);

  static bool classof(const SectionBase *s) {
    return s->kind() == SectionBase::Output;
  }

  static bool classof(const BaseCommand *c);

  uint64_t getLMA() const { return addr; }
  template <typename ELFT> void writeHeaderTo(typename ELFT::Shdr *sHdr);

  uint32_t sectionIndex = UINT32_MAX;
  unsigned sortRank;

  uint32_t getPhdrFlags() const;

  // Pointer to a relocation section for this section. Usually nullptr because
  // we consume relocations, but if --emit-relocs is specified (which is rare),
  // it may have a non-null value.
  OutputSection *relocationSection = nullptr;

  // Initially this field is the number of InputSections that have been added to
  // the OutputSection so far. Later on, after a call to assignAddresses, it
  // corresponds to the Elf_Shdr member.
  uint64_t size = 0;

  // The following fields correspond to Elf_Shdr members.
  uint64_t offset = 0;
  uint64_t addr = 0;
  uint32_t shName = 0;

  // void recordSection(InputSectionBase *isec);
  // void finalizeInputSections();

  // The following members are normally only used in linker scripts.
  // MemoryRegion *memRegion = nullptr;
  // MemoryRegion *lmaRegion = nullptr;
  Expr addrExpr;
  Expr alignExpr;
  Expr lmaExpr;
  Expr subalignExpr;
  std::vector<BaseCommand *> sectionCommands;
  std::vector<StringRef> phdrs;
  llvm::Optional<std::array<uint8_t, 4>> filler;
  ConstraintKind constraint = ConstraintKind::NoConstraint;
  std::string location;
  std::string memoryRegionName;
  std::string lmaRegionName;
  bool nonAlloc = false;
  bool noload = false;
  bool usedInExpression = false;
  bool inOverlay = false;

  // Tracks whether the section has ever had an input section added to it, even
  // if the section was later removed (e.g. because it is a synthetic section
  // that wasn't needed). This is needed for orphan placement.
  bool hasInputSections = false;

  void finalize();

private:
  std::array<uint8_t, 4> getFiller();
};

OutputSection::OutputSection(StringRef name, uint32_t type, uint64_t flags)
    : BaseCommand(OutputSectionKind),
      SectionBase(Output, name, flags, /*Entsize*/ 0, /*Alignment*/ 1, type,
                  /*Info*/ 0, /*Link*/ 0) {}

struct SymbolVersion {
  llvm::StringRef name;
  bool isExternCpp;
  bool hasWildcard;
};

// This struct contains symbols version definition that
// can be found in version script if it is used for link.
struct VersionDefinition {
  llvm::StringRef name;
  uint16_t id;
  std::vector<SymbolVersion> patterns;
};

//// This represents an r-value in the linker script.
// struct ExprValue {
//  ExprValue(SectionBase *sec, bool forceAbsolute, uint64_t val,
//            const Twine &loc)
//      : sec(sec), forceAbsolute(forceAbsolute), val(val), loc(loc.str()) {}
//
//  ExprValue(uint64_t val) : ExprValue(nullptr, false, val, "") {}
//
//  bool isAbsolute() const { return forceAbsolute || sec == nullptr; }
//  uint64_t getValue() const;
//  uint64_t getSecAddr() const;
//  uint64_t getSectionOffset() const;
//
//  // If a value is relative to a section, it has a non-null Sec.
//  SectionBase *sec;
//
//  // True if this expression is enclosed in ABSOLUTE().
//  // This flag affects the return value of getValue().
//  bool forceAbsolute;
//
//  uint64_t val;
//  uint64_t alignment = 1;
//
//  // Original source location. Used for error messages.
//  std::string loc;
//};

//===----------------------------------------------------------------------===//
// Lexer
//===----------------------------------------------------------------------===//

class ScriptLexer {
public:
  explicit ScriptLexer(MemoryBufferRef mb);

  void setError(const Twine &msg);
  void tokenize(MemoryBufferRef mb);
  static StringRef skipSpace(StringRef s);
  bool atEOF();
  StringRef next();
  StringRef peek();
  StringRef peek2();
  void skip();
  bool consume(StringRef tok);
  void expect(StringRef expect);
  bool consumeLabel(StringRef tok);
  std::string getCurrentLocation();

  std::vector<MemoryBufferRef> mbs;
  std::vector<StringRef> tokens;
  bool inExpr = false;
  size_t pos = 0;

private:
  void maybeSplitExpr();
  StringRef getLine();
  size_t getLineNumber();
  size_t getColumnNumber();

  MemoryBufferRef getCurrentMB();
};

// Returns a whole line containing the current token.
StringRef ScriptLexer::getLine() {
  StringRef s = getCurrentMB().getBuffer();
  StringRef tok = tokens[pos - 1];

  size_t pos = s.rfind('\n', tok.data() - s.data());
  if (pos != StringRef::npos)
    s = s.substr(pos + 1);
  return s.substr(0, s.find_first_of("\r\n"));
}

// Returns 1-based line number of the current token.
size_t ScriptLexer::getLineNumber() {
  StringRef s = getCurrentMB().getBuffer();
  StringRef tok = tokens[pos - 1];
  return s.substr(0, tok.data() - s.data()).count('\n') + 1;
}

// Returns 0-based column number of the current token.
size_t ScriptLexer::getColumnNumber() {
  StringRef tok = tokens[pos - 1];
  return tok.data() - getLine().data();
}

std::string ScriptLexer::getCurrentLocation() {
  std::string filename = getCurrentMB().getBufferIdentifier();
  return (filename + ":" + Twine(getLineNumber())).str();
}

ScriptLexer::ScriptLexer(MemoryBufferRef mb) { tokenize(mb); }

// We don't want to record cascading errors. Keep only the first one.
void ScriptLexer::setError(const Twine &msg) {
  if (errorCount())
    return;

  std::string s = (getCurrentLocation() + ":" +
                   std::to_string(getColumnNumber()) + ": " + msg)
                      .str();
  if (pos)
    s += "\n>>> " + getLine().str() + "\n>>> " +
         std::string(getColumnNumber(), ' ') + "^";
  error(s);
}

// Split S into linker script tokens.
void ScriptLexer::tokenize(MemoryBufferRef mb) {
  std::vector<StringRef> vec;
  mbs.push_back(mb);
  StringRef s = mb.getBuffer();
  StringRef begin = s;

  for (;;) {
    s = skipSpace(s);
    if (s.empty())
      break;

    // Quoted token. Note that double-quote characters are parts of a token
    // because, in a glob match context, only unquoted tokens are interpreted
    // as glob patterns. Double-quoted tokens are literal patterns in that
    // context.
    if (s.startswith("\"")) {
      size_t e = s.find("\"", 1);
      if (e == StringRef::npos) {
        StringRef filename = mb.getBufferIdentifier();
        size_t lineno = begin.substr(0, s.data() - begin.data()).count('\n');
        error(filename + ":" + Twine(lineno + 1) + ": unclosed quote");
        return;
      }

      vec.push_back(s.take_front(e + 1));
      s = s.substr(e + 1);
      continue;
    }

    // ">foo" is parsed to ">" and "foo", but ">>" is parsed to ">>".
    // "|", "||", "&" and "&&" are different operators.
    if (s.startswith("<<") || s.startswith("<=") || s.startswith(">>") ||
        s.startswith(">=") || s.startswith("||") || s.startswith("&&")) {
      vec.push_back(s.substr(0, 2));
      s = s.substr(2);
      continue;
    }

    // Unquoted token. This is more relaxed than tokens in C-like language,
    // so that you can write "file-name.cpp" as one bare token, for example.
    size_t pos = s.find_first_not_of(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789_.$/\\~=+[]*?-!^:");

    // A character that cannot start a word (which is usually a
    // punctuation) forms a single character token.
    if (pos == 0)
      pos = 1;
    vec.push_back(s.substr(0, pos));
    s = s.substr(pos);
  }

  tokens.insert(tokens.begin() + pos, vec.begin(), vec.end());
}

// Skip leading whitespace characters or comments.
StringRef ScriptLexer::skipSpace(StringRef s) {
  for (;;) {
    if (s.startswith("/*")) {
      size_t e = s.find("*/", 2);
      if (e == StringRef::npos) {
        error("unclosed comment in a linker script");
        return "";
      }
      s = s.substr(e + 2);
      continue;
    }
    if (s.startswith("#")) {
      size_t e = s.find('\n', 1);
      if (e == StringRef::npos)
        e = s.size() - 1;
      s = s.substr(e + 1);
      continue;
    }
    size_t size = s.size();
    s = s.ltrim();
    if (s.size() == size)
      return s;
  }
}

// An erroneous token is handled as if it were the last token before EOF.
bool ScriptLexer::atEOF() { return errorCount() || tokens.size() == pos; }

// Split a given string as an expression.
// This function returns "3", "*" and "5" for "3*5" for example.
static std::vector<StringRef> tokenizeExpr(StringRef s) {
  StringRef ops = "+-*/:!~=<>"; // List of operators

  // Quoted strings are literal strings, so we don't want to split it.
  if (s.startswith("\""))
    return {s};

  // Split S with operators as separators.
  std::vector<StringRef> ret;
  while (!s.empty()) {
    size_t e = s.find_first_of(ops);

    // No need to split if there is no operator.
    if (e == StringRef::npos) {
      ret.push_back(s);
      break;
    }

    // Get a token before the opreator.
    if (e != 0)
      ret.push_back(s.substr(0, e));

    // Get the operator as a token.
    // Keep !=, ==, >=, <=, << and >> operators as a single tokens.
    if (s.substr(e).startswith("!=") || s.substr(e).startswith("==") ||
        s.substr(e).startswith(">=") || s.substr(e).startswith("<=") ||
        s.substr(e).startswith("<<") || s.substr(e).startswith(">>")) {
      ret.push_back(s.substr(e, 2));
      s = s.substr(e + 2);
    } else {
      ret.push_back(s.substr(e, 1));
      s = s.substr(e + 1);
    }
  }
  return ret;
}

// In contexts where expressions are expected, the lexer should apply
// different tokenization rules than the default one. By default,
// arithmetic operator characters are regular characters, but in the
// expression context, they should be independent tokens.
//
// For example, "foo*3" should be tokenized to "foo", "*" and "3" only
// in the expression context.
//
// This function may split the current token into multiple tokens.
void ScriptLexer::maybeSplitExpr() {
  if (!inExpr || errorCount() || atEOF())
    return;

  std::vector<StringRef> v = tokenizeExpr(tokens[pos]);
  if (v.size() == 1)
    return;
  tokens.erase(tokens.begin() + pos);
  tokens.insert(tokens.begin() + pos, v.begin(), v.end());
}

StringRef ScriptLexer::next() {
  maybeSplitExpr();

  if (errorCount())
    return "";
  if (atEOF()) {
    setError("unexpected EOF");
    return "";
  }
  return tokens[pos++];
}

StringRef ScriptLexer::peek() {
  StringRef tok = next();
  if (errorCount())
    return "";
  pos = pos - 1;
  return tok;
}

StringRef ScriptLexer::peek2() {
  skip();
  StringRef tok = next();
  if (errorCount())
    return "";
  pos = pos - 2;
  return tok;
}

bool ScriptLexer::consume(StringRef tok) {
  if (peek() == tok) {
    skip();
    return true;
  }
  return false;
}

// Consumes Tok followed by ":". Space is allowed between Tok and ":".
bool ScriptLexer::consumeLabel(StringRef tok) {
  if (consume((tok + ":").str()))
    return true;
  if (tokens.size() >= pos + 2 && tokens[pos] == tok &&
      tokens[pos + 1] == ":") {
    pos += 2;
    return true;
  }
  return false;
}

void ScriptLexer::skip() { (void)next(); }

void ScriptLexer::expect(StringRef expect) {
  if (errorCount())
    return;
  StringRef tok = next();
  if (tok != expect)
    setError(expect + " expected, but got " + tok);
}

// Returns true if S encloses T.
static bool encloses(StringRef s, StringRef t) {
  return s.bytes_begin() <= t.bytes_begin() && t.bytes_end() <= s.bytes_end();
}

MemoryBufferRef ScriptLexer::getCurrentMB() {
  // Find input buffer containing the current token.
  assert(!mbs.empty() && pos > 0);
  for (MemoryBufferRef mb : mbs)
    if (encloses(mb.getBuffer(), tokens[pos - 1]))
      return mb;
  llvm_unreachable("getCurrentMB: failed to find a token");
}

//===----------------------------------------------------------------------===//
// Parser
//===----------------------------------------------------------------------===//

// Parses a linker script. Calling this function updates
// lld::elf::config and lld::elf::script.
void readLinkerScript(MemoryBufferRef mb);

// Parses a version script.
void readVersionScript(MemoryBufferRef mb);

void readDynamicList(MemoryBufferRef mb);

// Parses the defsym expression.
void readDefsym(StringRef name, MemoryBufferRef mb);

class ScriptParser final : ScriptLexer {
public:
  ScriptParser(MemoryBufferRef mb) : ScriptLexer(mb) {}

  void readLinkerScript();
  void readVersionScript();
  void readDynamicList();
  void readDefsym(StringRef name);

private:
  void addFile(StringRef path);

  void readAsNeeded();
  void readEntry();
  void readExtern();
  void readGroup();
  void readInclude();
  void readInput();
  void readMemory();
  void readOutput();
  void readOutputArch();
  void readOutputFormat();
  void readPhdrs();
  void readRegionAlias();
  void readSearchDir();
  void readSections();
  void readTarget();
  void readVersion();
  void readVersionScriptCommand();

  SymbolAssignment *readSymbolAssignment(StringRef name);
  ByteCommand *readByteCommand(StringRef tok);
  Expr readFill();
  bool readSectionDirective(OutputSection *cmd, StringRef tok1, StringRef tok2);
  void readSectionAddressType(OutputSection *cmd);
  OutputSection *readOverlaySectionDescription();
  OutputSection *readOutputSectionDescription(StringRef outSec);
  std::vector<BaseCommand *> readOverlay();
  std::vector<StringRef> readOutputSectionPhdrs();
  InputSectionDescription *readInputSectionDescription(StringRef tok);
  StringMatcher readFilePatterns();
  std::vector<SectionPattern> readInputSectionsList();
  InputSectionDescription *readInputSectionRules(StringRef filePattern);
  unsigned readPhdrType();
  SortSectionPolicy readSortKind();
  SymbolAssignment *readProvideHidden(bool provide, bool hidden);
  SymbolAssignment *readAssignment(StringRef tok);
  void readSort();
  Expr readAssert();
  Expr readConstant();

  Expr readMemoryAssignment(StringRef, StringRef, StringRef);
  std::pair<uint32_t, uint32_t> readMemoryAttributes();

  Expr combine(StringRef op, Expr l, Expr r);
  Expr readExpr();
  Expr readExpr1(Expr lhs, int minPrec);
  StringRef readParenLiteral();
  Expr readPrimary();
  Expr readTernary(Expr cond);
  Expr readParenExpr();

  // For parsing version script.
  std::vector<SymbolVersion> readVersionExtern();
  void readAnonymousDeclaration();
  void readVersionDeclaration(StringRef verStr);

  std::pair<std::vector<SymbolVersion>, std::vector<SymbolVersion>>
  readSymbols();

  // A set to detect an INCLUDE() cycle.
  StringSet<> seen;

  // A map from memory region name to a memory region descriptor.
  llvm::MapVector<llvm::StringRef, MemoryRegion *> memoryRegions;
  
  // SECTIONS command list.
  llvm::DenseMap<StringRef, OutputSection *> nameToOutputSection;
  std::vector<BaseCommand *> sectionCommands;
};

static StringRef unquote(StringRef s) {
  if (s.startswith("\""))
    return s.substr(1, s.size() - 2);
  return s;
}

// Some operations only support one non absolute value. Move the
// absolute one to the right hand side for convenience.
static void moveAbsRight(Expr &a, Expr &b) {
  // if (a.sec == nullptr || (a.forceAbsolute && !b.isAbsolute()))
  //  std::swap(a, b);
  // TODO if (!b.isAbsolute())
  //  error(a.loc + ": at least one side of the expression must be absolute");
}

static Expr add(Expr a, Expr b) {
  moveAbsRight(a, b);
  return a; // TODO a op b
}

static Expr sub(Expr a, Expr b) {
  return a; // TODO a op b
}

static Expr mul(Expr a, Expr b) {
  return a; // TODO a op b
}

static Expr div(Expr a, Expr b) {
  // error(loc + ": division by zero");
  return a; // TODO a op b
}

static Expr mod(Expr a, Expr b) {
  // error(loc + ": modulo by zero");
  return a; // TODO a op b
}

static Expr bitAnd(Expr a, Expr b) {
  moveAbsRight(a, b);
  return a; // TODO a op b
}

static Expr bitOr(Expr a, Expr b) {
  moveAbsRight(a, b);
  return a; // TODO a op b
}

static Expr lShift(Expr a, Expr b) {
  return a; // TODO a op b
}

static Expr rShift(Expr a, Expr b) {
  return a; // TODO a op b
}

static Expr min(Expr a, Expr b) {
  return a; // TODO a op b
}

static Expr max(Expr a, Expr b) {
  return a; // TODO a op b
}

static Expr call(StringRef f) {
  return Expr(); // TODO f(a)
}

static Expr call(StringRef f, StringRef a) {
  return Expr(); // TODO f(a)
}

static Expr call(StringRef f, Expr a) {
  return a; // TODO f(a)
}

static Expr call(StringRef f, Expr a, Expr b) {
  return a; // TODO f(a, b)
}

void ScriptParser::readDynamicList() {
  expect("{");
  std::vector<SymbolVersion> locals;
  std::vector<SymbolVersion> globals;
  std::tie(locals, globals) = readSymbols();
  expect(";");

  if (!atEOF()) {
    setError("EOF expected, but got " + next());
    return;
  }
  if (!locals.empty()) {
    setError("\"local:\" scope not supported in --dynamic-list");
    return;
  }

  for (SymbolVersion v : globals)
    ;
  // TODO
}

void ScriptParser::readVersionScript() {
  readVersionScriptCommand();
  if (!atEOF())
    setError("EOF expected, but got " + next());
}

void ScriptParser::readVersionScriptCommand() {
  if (consume("{")) {
    readAnonymousDeclaration();
    return;
  }

  while (!atEOF() && !errorCount() && peek() != "}") {
    StringRef verStr = next();
    if (verStr == "{") {
      setError("anonymous version definition is used in "
               "combination with other version definitions");
      return;
    }
    expect("{");
    readVersionDeclaration(verStr);
  }
}

void ScriptParser::readVersion() {
  expect("{");
  readVersionScriptCommand();
  expect("}");
}

void ScriptParser::readLinkerScript() {
  while (!atEOF()) {
    StringRef tok = next();
    if (tok == ";")
      continue;

    if (tok == "ENTRY") {
      readEntry();
    } else if (tok == "EXTERN") {
      readExtern();
    } else if (tok == "GROUP") {
      readGroup();
    } else if (tok == "INCLUDE") {
      readInclude();
    } else if (tok == "INPUT") {
      readInput();
    } else if (tok == "MEMORY") {
      readMemory();
    } else if (tok == "OUTPUT") {
      readOutput();
    } else if (tok == "OUTPUT_ARCH") {
      readOutputArch();
    } else if (tok == "OUTPUT_FORMAT") {
      readOutputFormat();
    } else if (tok == "PHDRS") {
      readPhdrs();
    } else if (tok == "REGION_ALIAS") {
      readRegionAlias();
    } else if (tok == "SEARCH_DIR") {
      readSearchDir();
    } else if (tok == "SECTIONS") {
      readSections();
    } else if (tok == "TARGET") {
      readTarget();
    } else if (tok == "VERSION") {
      readVersion();
    } else if (SymbolAssignment *cmd = readAssignment(tok)) {
      // TODO script->sectionCommands.push_back(cmd);
    } else {
      setError("unknown directive: " + tok);
    }
  }
}

void ScriptParser::readDefsym(StringRef name) {
  if (errorCount())
    return;
  Expr e = readExpr();
  if (!atEOF())
    setError("EOF expected, but got " + next());
  //SymbolAssignment *cmd = make<SymbolAssignment>(name, e, getCurrentLocation());
  // TODO script->sectionCommands.push_back(cmd);
}

void ScriptParser::addFile(StringRef s) {
  // TODO
}

void ScriptParser::readAsNeeded() {
  expect("(");
  while (!errorCount() && !consume(")"))
    addFile(unquote(next()));
}

void ScriptParser::readEntry() {
  // -e <symbol> takes predecence over ENTRY(<symbol>).
  expect("(");
  StringRef tok = next();
  // TODO
  expect(")");
}

void ScriptParser::readExtern() {
  expect("(");
  while (!errorCount() && !consume(")")) {
    std::string undef = unquote(next());
    // TODO config->undefined.push_back(change name from undef
  }
}

void ScriptParser::readGroup() { readInput(); }

std::vector<llvm::StringRef> SearchPaths; // TODO set search paths
Optional<std::string> searchScript(StringRef name) {
  if (FILE *f = fopen(name.str().c_str(), "r")) {
    fclose(f);
    return name.str();
  }
  for (StringRef dir : SearchPaths) {
    SmallString<128> s;
    path::append(s, dir, name);
    if (FILE *f = fopen(name.str().c_str(), "r")) {
      fclose(f);
      return name.str();
    }
  }
  return None;
}

void ScriptParser::readInclude() {
  StringRef tok = unquote(next());

  if (!seen.insert(tok).second) {
    setError("there is a cycle in linker script INCLUDEs");
    return;
  }

  if (Optional<std::string> path = searchScript(tok)) {
    if (auto mb = readFile(*path))
      tokenize(*mb);
    return;
  }
  setError("cannot find linker script " + tok);
}

void ScriptParser::readInput() {
  expect("(");
  while (!errorCount() && !consume(")")) {
    if (consume("AS_NEEDED"))
      readAsNeeded();
    else
      addFile(unquote(next()));
  }
}

void ScriptParser::readOutput() {
  // -o <file> takes predecence over OUTPUT(<file>).
  expect("(");
  StringRef tok = next();
  // TODO  config->outputFile = unquote(tok);
  expect(")");
}

void ScriptParser::readOutputArch() {
  // OUTPUT_ARCH is ignored for now.
  expect("(");
  while (!errorCount() && !consume(")"))
    skip();
}

// Parse OUTPUT_FORMAT(bfdname) or OUTPUT_FORMAT(bfdname, big, little).
// Currently we ignore big and little parameters.
void ScriptParser::readOutputFormat() {
  expect("(");

  StringRef name = unquote(next());
  StringRef s = name;
  // TODO

  if (consume(")"))
    return;
  expect(",");
  skip();
  expect(",");
  skip();
  expect(")");
}

void ScriptParser::readPhdrs() {
  expect("{");

  while (!errorCount() && !consume("}")) {
    PhdrsCommand cmd;
    cmd.name = next();
    cmd.type = readPhdrType();

    while (!errorCount() && !consume(";")) {
      if (consume("FILEHDR"))
        cmd.hasFilehdr = true;
      else if (consume("PHDRS"))
        cmd.hasPhdrs = true;
      else if (consume("AT"))
        cmd.lmaExpr = readParenExpr();
      else if (consume("FLAGS"))
        cmd.flags = readParenExpr();
      else
        setError("unexpected header attribute: " + next());
    }

    // TODO script->phdrsCommands.push_back(cmd);
  }
}

void ScriptParser::readRegionAlias() {
  expect("(");
  StringRef alias = unquote(next());
  expect(",");
  StringRef name = next();
  expect(")");

  if (memoryRegions.count(alias))
    setError("redefinition of memory region '" + alias + "'");
  if (!memoryRegions.count(name))
    setError("memory region '" + name + "' is not defined");
  memoryRegions.insert({alias, memoryRegions[name]});
}

void ScriptParser::readSearchDir() {
  expect("(");
  StringRef tok = next();
  // TODO  config->searchPaths.push_back(unquote(tok));
  expect(")");
}

// This reads an overlay description. Overlays are used to describe output
// sections that use the same virtual memory range and normally would trigger
// linker's sections sanity check failures.
// https://sourceware.org/binutils/docs/ld/Overlay-Description.html#Overlay-Description
std::vector<BaseCommand *> ScriptParser::readOverlay() {
  // VA and LMA expressions are optional, though for simplicity of
  // implementation we assume they are not. That is what OVERLAY was designed
  // for first of all: to allow sections with overlapping VAs at different LMAs.
  Expr addrExpr = readExpr();
  expect(":");
  expect("AT");
  Expr lmaExpr = readParenExpr();
  expect("{");

  std::vector<BaseCommand *> v;
  while (!errorCount() && !consume("}")) {
    // VA is the same for all sections. The LMAs are consecutive in memory
    // starting from the base load address specified.
    OutputSection *os = readOverlaySectionDescription();
    os->addrExpr = addrExpr;
    os->lmaExpr = lmaExpr;
    v.push_back(os);
  }
  return v;
}

void ScriptParser::readSections() {
  expect("{");
  std::vector<BaseCommand *> v;
  while (!errorCount() && !consume("}")) {
    StringRef tok = next();
    if (tok == "OVERLAY") {
      for (BaseCommand *cmd : readOverlay())
        v.push_back(cmd);
      continue;
    } else if (tok == "INCLUDE") {
      readInclude();
      continue;
    }

    if (BaseCommand *cmd = readAssignment(tok))
      v.push_back(cmd);
    else
      v.push_back(readOutputSectionDescription(tok));
  }

  if (!atEOF() && consume("INSERT")) {
    //std::vector<BaseCommand *> *dest = nullptr;
    if (consume("AFTER"))
      ;
    else if (consume("BEFORE"))
      ;
    else
      setError("expected AFTER/BEFORE, but got '" + next() + "'");
    // TODO
    return;
  }

  sectionCommands.insert(sectionCommands.end(), v.begin(), v.end());
}

void ScriptParser::readTarget() {
  // TARGET(foo)
  expect("(");
  StringRef tok = next();
  expect(")");

  // TODO
}

static int precedence(StringRef op) {
  return StringSwitch<int>(op)
      .Cases("*", "/", "%", 8)
      .Cases("+", "-", 7)
      .Cases("<<", ">>", 6)
      .Cases("<", "<=", ">", ">=", "==", "!=", 5)
      .Case("&", 4)
      .Case("|", 3)
      .Case("&&", 2)
      .Case("||", 1)
      .Default(-1);
}

StringMatcher ScriptParser::readFilePatterns() {
  std::vector<StringRef> v;
  while (!errorCount() && !consume(")"))
    v.push_back(next());
  // return StringMatcher(v); TODO: squash them togheter in 1 string or change
  // string matcher class?
  return StringMatcher(v.front());
}

SortSectionPolicy ScriptParser::readSortKind() {
  if (consume("SORT") || consume("SORT_BY_NAME"))
    return SortSectionPolicy::Name;
  if (consume("SORT_BY_ALIGNMENT"))
    return SortSectionPolicy::Alignment;
  if (consume("SORT_BY_INIT_PRIORITY"))
    return SortSectionPolicy::Priority;
  if (consume("SORT_NONE"))
    return SortSectionPolicy::None;
  return SortSectionPolicy::Default;
}

// Reads SECTIONS command contents in the following form:
//
// <contents> ::= <elem>*
// <elem>     ::= <exclude>? <glob-pattern>
// <exclude>  ::= "EXCLUDE_FILE" "(" <glob-pattern>+ ")"
//
// For example,
//
// *(.foo EXCLUDE_FILE (a.o) .bar EXCLUDE_FILE (b.o) .baz)
//
// is parsed as ".foo", ".bar" with "a.o", and ".baz" with "b.o".
// The semantics of that is section .foo in any file, section .bar in
// any file but a.o, and section .baz in any file but b.o.
std::vector<SectionPattern> ScriptParser::readInputSectionsList() {
  std::vector<SectionPattern> ret;
  while (!errorCount() && peek() != ")") {
    StringMatcher excludeFilePat;
    if (consume("EXCLUDE_FILE")) {
      expect("(");
      excludeFilePat = readFilePatterns();
    }

    std::vector<StringRef> v;
    while (!errorCount() && peek() != ")" && peek() != "EXCLUDE_FILE")
      v.push_back(unquote(next()));

    if (!v.empty())
      ; // TODO ret.push_back({std::move(excludeFilePat), StringMatcher(v)});
    else
      setError("section pattern is expected");
  }
  return ret;
}

// Reads contents of "SECTIONS" directive. That directive contains a
// list of glob patterns for input sections. The grammar is as follows.
//
// <patterns> ::= <section-list>
//              | <sort> "(" <section-list> ")"
//              | <sort> "(" <sort> "(" <section-list> ")" ")"
//
// <sort>     ::= "SORT" | "SORT_BY_NAME" | "SORT_BY_ALIGNMENT"
//              | "SORT_BY_INIT_PRIORITY" | "SORT_NONE"
//
// <section-list> is parsed by readInputSectionsList().
InputSectionDescription *
ScriptParser::readInputSectionRules(StringRef filePattern) {
  auto *cmd = make<InputSectionDescription>(filePattern);
  expect("(");

  while (!errorCount() && !consume(")")) {
    SortSectionPolicy outer = readSortKind();
    SortSectionPolicy inner = SortSectionPolicy::Default;
    std::vector<SectionPattern> v;
    if (outer != SortSectionPolicy::Default) {
      expect("(");
      inner = readSortKind();
      if (inner != SortSectionPolicy::Default) {
        expect("(");
        v = readInputSectionsList();
        expect(")");
      } else {
        v = readInputSectionsList();
      }
      expect(")");
    } else {
      v = readInputSectionsList();
    }

    for (SectionPattern &pat : v) {
      pat.sortInner = inner;
      pat.sortOuter = outer;
    }

    // TODO std::move(v.begin(), v.end(),
    // std::back_inserter(cmd->sectionPatterns));
  }
  return cmd;
}

InputSectionDescription *
ScriptParser::readInputSectionDescription(StringRef tok) {
  // Input section wildcard can be surrounded by KEEP.
  // https://sourceware.org/binutils/docs/ld/Input-Section-Keep.html#Input-Section-Keep
  if (tok == "KEEP") {
    expect("(");
    StringRef filePattern = next();
    InputSectionDescription *cmd = readInputSectionRules(filePattern);
    expect(")");
    // TODO script->keptSections.push_back(cmd);
    return cmd;
  }
  return readInputSectionRules(tok);
}

void ScriptParser::readSort() {
  expect("(");
  expect("CONSTRUCTORS");
  expect(")");
}

Expr ScriptParser::readAssert() {
  expect("(");
  Expr e = readExpr();
  expect(",");
  StringRef msg = unquote(next());
  expect(")");

  // todo return e (msg)
  return e;
}

// Tries to read the special directive for an output section definition which
// can be one of following: "(NOLOAD)", "(COPY)", "(INFO)" or "(OVERLAY)".
// Tok1 and Tok2 are next 2 tokens peeked. See comment for
// readSectionAddressType below.
bool ScriptParser::readSectionDirective(OutputSection *cmd, StringRef tok1,
                                        StringRef tok2) {
  if (tok1 != "(")
    return false;
  if (tok2 != "NOLOAD" && tok2 != "COPY" && tok2 != "INFO" && tok2 != "OVERLAY")
    return false;

  expect("(");
  if (consume("NOLOAD")) {
    cmd->noload = true;
  } else {
    skip(); // This is "COPY", "INFO" or "OVERLAY".
    cmd->nonAlloc = true;
  }
  expect(")");
  return true;
}

// Reads an expression and/or the special directive for an output
// section definition. Directive is one of following: "(NOLOAD)",
// "(COPY)", "(INFO)" or "(OVERLAY)".
//
// An output section name can be followed by an address expression
// and/or directive. This grammar is not LL(1) because "(" can be
// interpreted as either the beginning of some expression or beginning
// of directive.
//
// https://sourceware.org/binutils/docs/ld/Output-Section-Address.html
// https://sourceware.org/binutils/docs/ld/Output-Section-Type.html
void ScriptParser::readSectionAddressType(OutputSection *cmd) {
  if (readSectionDirective(cmd, peek(), peek2()))
    return;

  cmd->addrExpr = readExpr();
  if (peek() == "(" && !readSectionDirective(cmd, "(", peek2()))
    setError("unknown section directive: " + peek2());
}

static Expr checkAlignment(Expr e, std::string &loc) {
  // TODO
  // if (!isPowerOf2_64(e -> alignment)) {
  //    error(loc + ": alignment must be power of 2");
  return e;
}

OutputSection *ScriptParser::readOverlaySectionDescription() {
  OutputSection *cmd = make<OutputSection>(next(), SHT_PROGBITS, 0);
  cmd->location =
      getCurrentLocation(); // TODO is this correct or next location?
  cmd->inOverlay = true;
  expect("{");
  while (!errorCount() && !consume("}"))
    cmd->sectionCommands.push_back(readInputSectionRules(next()));
  cmd->phdrs = readOutputSectionPhdrs();
  return cmd;
}

OutputSection *ScriptParser::readOutputSectionDescription(StringRef outSec) {
  OutputSection *cmd = make<OutputSection>(outSec, SHT_PROGBITS, 0);
  cmd->location = getCurrentLocation();

  if (peek() != ":")
    readSectionAddressType(cmd);
  expect(":");

  std::string location = getCurrentLocation();
  if (consume("AT"))
    cmd->lmaExpr = readParenExpr();
  if (consume("ALIGN"))
    cmd->alignExpr = checkAlignment(readParenExpr(), location);
  if (consume("SUBALIGN"))
    cmd->subalignExpr = checkAlignment(readParenExpr(), location);

  // Parse constraints.
  if (consume("ONLY_IF_RO"))
    cmd->constraint = ConstraintKind::ReadOnly;
  if (consume("ONLY_IF_RW"))
    cmd->constraint = ConstraintKind::ReadWrite;
  expect("{");

  while (!errorCount() && !consume("}")) {
    StringRef tok = next();
    if (tok == ";") {
      // Empty commands are allowed. Do nothing here.
    } else if (SymbolAssignment *assign = readAssignment(tok)) {
      cmd->sectionCommands.push_back(assign);
    } else if (ByteCommand *data = readByteCommand(tok)) {
      cmd->sectionCommands.push_back(data);
    } else if (tok == "CONSTRUCTORS") {
      // CONSTRUCTORS is a keyword to make the linker recognize C++ ctors/dtors
      // by name. This is for very old file formats such as ECOFF/XCOFF.
      // For ELF, we should ignore.
    } else if (tok == "FILL") {
      // We handle the FILL command as an alias for =fillexp section attribute,
      // which is different from what GNU linkers do.
      // https://sourceware.org/binutils/docs/ld/Output-Section-Data.html
      expect("(");
      Expr e = readFill();
      // TODO USE IT
      expect(")");
    } else if (tok == "SORT") {
      readSort();
    } else if (tok == "INCLUDE") {
      readInclude();
    } else if (peek() == "(") {
      cmd->sectionCommands.push_back(readInputSectionDescription(tok));
    } else {
      // We have a file name and no input sections description. It is not a
      // commonly used syntax, but still acceptable. In that case, all sections
      // from the file will be included.
      // TODO
      // cmd->sectionCommands.push_back(isd);
    }
  }

  if (consume(">"))
    cmd->memoryRegionName = next();

  if (consume("AT")) {
    expect(">");
    cmd->lmaRegionName = next();
  }

  // todo
  // if (cmd->lmaExpr && !cmd->lmaRegionName.empty())
  //  error("section can't have both LMA and a load region");

  cmd->phdrs = readOutputSectionPhdrs();

  if (peek() == "=" || peek().startswith("=")) {
    inExpr = true;
    consume("=");
    Expr e = readFill();
    // TODO USE it
    inExpr = false;
  }

  // Consume optional comma following output section command.
  consume(",");

  return cmd;
}

// Reads a `=<fillexp>` expression and returns its value as a big-endian number.
// https://sourceware.org/binutils/docs/ld/Output-Section-Fill.html
// We do not support using symbols in such expressions.
//
// When reading a hexstring, ld.bfd handles it as a blob of arbitrary
// size, while ld.gold always handles it as a 32-bit big-endian number.
// We are compatible with ld.gold because it's easier to implement.
Expr ScriptParser::readFill() {
  Expr e = readExpr();
  uint64_t value = 0; // TODO E -> VALUE
  if (value > UINT32_MAX)
    setError("filler expression result does not fit 32-bit: 0x" +
             Twine::utohexstr(value));

  return e;
}

SymbolAssignment *ScriptParser::readProvideHidden(bool provide, bool hidden) {
  expect("(");
  SymbolAssignment *cmd = readSymbolAssignment(next());
  cmd->provide = provide;
  cmd->hidden = hidden;
  expect(")");
  return cmd;
}

SymbolAssignment *ScriptParser::readAssignment(StringRef tok) {
  // Assert expression returns Dot, so this is equal to ".=."
  if (tok == "ASSERT")
    return make<SymbolAssignment>(".", readAssert(), getCurrentLocation());

  size_t oldPos = pos;
  SymbolAssignment *cmd = nullptr;
  if (peek() == "=" || peek() == "+=")
    cmd = readSymbolAssignment(tok);
  else if (tok == "PROVIDE")
    cmd = readProvideHidden(true, false);
  else if (tok == "HIDDEN")
    cmd = readProvideHidden(false, true);
  else if (tok == "PROVIDE_HIDDEN")
    cmd = readProvideHidden(true, true);

  if (cmd) {
    cmd->commandString =
        tok.str() + " " +
        llvm::join(tokens.begin() + oldPos, tokens.begin() + pos, " ");
    expect(";");
  }
  return cmd;
}

SymbolAssignment *ScriptParser::readSymbolAssignment(StringRef name) {
  StringRef op = next();
  assert(op == "=" || op == "+=");
  Expr e = readExpr();
  if (op == "+=") {
    // TODO e = add (name, e);
  }
  return make<SymbolAssignment>(name, e, getCurrentLocation());
}

// This is an operator-precedence parser to parse a linker
// script expression.
Expr ScriptParser::readExpr() {
  // Our lexer is context-aware. Set the in-expression bit so that
  // they apply different tokenization rules.
  bool orig = inExpr;
  inExpr = true;
  Expr e = readExpr1(readPrimary(), 0);
  inExpr = orig;
  return e;
}

Expr ScriptParser::combine(StringRef op, Expr l, Expr r) {
  if (op == "+")
    return add(l, r);
  if (op == "-")
    return sub(l, r);
  if (op == "*")
    return mul(l, r);
  if (op == "/")
    return div(l, r);
  if (op == "%")
    return mod(l, r);
  if (op == "<<")
    return lShift(l, r);
  if (op == ">>")
    return rShift(l, r);
  if (op == "<")
    return l; // TODO add a function like add
  if (op == ">")
    return l; // TODO add a function like add
  if (op == ">=")
    return l; // TODO add a function like add
  if (op == "<=")
    return l; // TODO add a function like add
  if (op == "==")
    return l; // TODO add a function like add
  if (op == "!=")
    return l; // TODO add a function like add
  if (op == "||")
    return l; // TODO add a function like add
  if (op == "&&")
    return l; // TODO add a function like add
  if (op == "&")
    return bitAnd(l, r);
  if (op == "|")
    return bitOr(l, r);
  llvm_unreachable("invalid operator");
}

// This is a part of the operator-precedence parser. This function
// assumes that the remaining token stream starts with an operator.
Expr ScriptParser::readExpr1(Expr lhs, int minPrec) {
  while (!atEOF() && !errorCount()) {
    // Read an operator and an expression.
    if (consume("?"))
      return readTernary(lhs);
    StringRef op1 = peek();
    if (precedence(op1) < minPrec)
      break;
    skip();
    Expr rhs = readPrimary();

    // Evaluate the remaining part of the expression first if the
    // next operator has greater precedence than the previous one.
    // For example, if we have read "+" and "3", and if the next
    // operator is "*", then we'll evaluate 3 * ... part first.
    while (!atEOF()) {
      StringRef op2 = peek();
      if (precedence(op2) <= precedence(op1))
        break;
      rhs = readExpr1(rhs, precedence(op2));
    }

    lhs = combine(op1, lhs, rhs);
  }
  return lhs;
}

Expr ScriptParser::readConstant() {
  StringRef s = readParenLiteral();
  if (s == "COMMONPAGESIZE")
    return call("COMMONPAGESIZE");
  if (s == "MAXPAGESIZE")
    return call("MAXPAGESIZE");
  if (s == "MIRRORAREASTART")
    return call("MIRRORAREASTART");
  setError("unknown constant: " + s);
  return Expr();
}

// Parses Tok as an integer. It recognizes hexadecimal (prefixed with
// "0x" or suffixed with "H") and decimal numbers. Decimal numbers may
// have "K" (Ki) or "M" (Mi) suffixes.
static Optional<uint64_t> parseInt(StringRef tok) {
  // Hexadecimal
  uint64_t val;
  if (tok.startswith_lower("0x")) {
    if (!to_integer(tok.substr(2), val, 16))
      return None;
    return val;
  }
  if (tok.endswith_lower("H")) {
    if (!to_integer(tok.drop_back(), val, 16))
      return None;
    return val;
  }

  // Decimal
  if (tok.endswith_lower("K")) {
    if (!to_integer(tok.drop_back(), val, 10))
      return None;
    return val * 1024;
  }
  if (tok.endswith_lower("M")) {
    if (!to_integer(tok.drop_back(), val, 10))
      return None;
    return val * 1024 * 1024;
  }
  if (!to_integer(tok, val, 10))
    return None;
  return val;
}

ByteCommand *ScriptParser::readByteCommand(StringRef tok) {
  int size = StringSwitch<int>(tok)
                 .Case("BYTE", 1)
                 .Case("SHORT", 2)
                 .Case("LONG", 4)
                 .Case("QUAD", 8)
                 .Default(-1);
  if (size == -1)
    return nullptr;

  size_t oldPos = pos;
  Expr e = readParenExpr();
  std::string commandString =
      tok.str() + " " +
      llvm::join(tokens.begin() + oldPos, tokens.begin() + pos, " ");
  return make<ByteCommand>(e, size, commandString);
}

StringRef ScriptParser::readParenLiteral() {
  expect("(");
  bool orig = inExpr;
  inExpr = false;
  StringRef tok = next();
  inExpr = orig;
  expect(")");
  return tok;
}

bool isValidCIdentifier(StringRef s) {
  return !s.empty() && (isAlpha(s[0]) || s[0] == '_') &&
         std::all_of(s.begin() + 1, s.end(),
                     [](char c) { return c == '_' || isAlnum(c); });
}

Expr ScriptParser::readPrimary() {
  if (peek() == "(")
    return readParenExpr();

  if (consume("~")) {
    return readPrimary();
  }
  if (consume("!")) {
    return readPrimary();
  }
  if (consume("-")) {
    return readPrimary();
  }

  StringRef tok = next();
  std::string location = getCurrentLocation();

  // Built-in functions are parsed here.
  // https://sourceware.org/binutils/docs/ld/Builtin-Functions.html.
  if (tok == "ABSOLUTE") {
    Expr inner = readParenExpr();
    return call("ABSOLUTE", inner);
  }
  if (tok == "ADDR") {
    StringRef name = readParenLiteral();
    return call("ADDR", name);
  }
  if (tok == "ALIGN") {
    expect("(");
    Expr e = readExpr();
    if (consume(")")) {
      e = checkAlignment(e, location);
      return call("ALIGN", e);
    }
    expect(",");
    Expr e2 = checkAlignment(readExpr(), location);
    expect(")");
    return call("ALIGN", e, e2);
  }
  if (tok == "ALIGNOF") {
    StringRef name = readParenLiteral();
    return call("ALIGNOF", name);
  }
  if (tok == "ASSERT")
    return readAssert();
  if (tok == "CONSTANT")
    return readConstant();
  if (tok == "DATA_SEGMENT_ALIGN") {
    expect("(");
    Expr e1 = readExpr();
    expect(",");
    Expr e2 = readExpr();
    expect(")");
    return call("DATA_SEGMENT_ALIGN", e1, e2);
  }
  if (tok == "DATA_SEGMENT_END") {
    expect("(");
    expect(".");
    expect(")");
    return call("DATA_SEGMENT_END");
  }
  if (tok == "DATA_SEGMENT_RELRO_END") {
    // GNU linkers implements more complicated logic to handle
    // DATA_SEGMENT_RELRO_END. We instead ignore the arguments and
    // just align to the next page boundary for simplicity.
    expect("(");
    Expr offset = readExpr();
    expect(",");
    Expr e = readExpr();
    expect(")");
    return call("DATA_SEGMENT_RELRO_END", offset, e);
  }
  if (tok == "DEFINED") {
    StringRef name = readParenLiteral();
    return call("DEFINED", name);
  }
  if (tok == "LENGTH") {
    StringRef name = readParenLiteral();
    if (memoryRegions.count(name) == 0)
      setError("memory region not defined: " + name);
    return call("LENGTH", name);
  }
  if (tok == "LOADADDR") {
    StringRef name = readParenLiteral();
    return call("LOADADDR", name);
  }
  if (tok == "MAX" || tok == "MIN") {
    expect("(");
    Expr a = readExpr();
    expect(",");
    Expr b = readExpr();
    expect(")");
    if (tok == "MIN")
      return min(a, b);
    return max(a, b);
  }
  if (tok == "ORIGIN") {
    StringRef name = readParenLiteral();
    if (memoryRegions.count(name) == 0)
      setError("memory region not defined: " + name);
    return call("SIZEOF", name);
  }
  if (tok == "SEGMENT_START") {
    expect("(");
    StringRef tok = next(); // Todo change to expr
    Expr e1;
    expect(",");
    Expr e2 = readExpr();
    expect(")");
    return call("SEGMENT_START", e1, e2);
  }
  if (tok == "SIZEOF") {
    StringRef name = readParenLiteral();
    return call("SIZEOF", name);
  }
  if (tok == "SIZEOF_HEADERS")
    return call("SIZEOF_HEADERS");

  // Tok is the dot.
  if (tok == ".")
    return Expr(); // TODO DOT EXPR

  // Tok is a literal number.
  if (Optional<uint64_t> val = parseInt(tok))
    return Expr(); // TODO number expr

  // Tok is a symbol name.
  if (!isValidCIdentifier(tok))
    setError("malformed number: " + tok);
  // script->referencedSymbols.push_back(tok);
  return Expr(); // TODO symbol expr
}

Expr ScriptParser::readTernary(Expr cond) {
  Expr l = readExpr();
  expect(":");
  Expr r = readExpr();
  return l; // TODO USE R AS WELL FOR TERNARY
}

Expr ScriptParser::readParenExpr() {
  expect("(");
  Expr e = readExpr();
  expect(")");
  return e;
}

std::vector<StringRef> ScriptParser::readOutputSectionPhdrs() {
  std::vector<StringRef> phdrs;
  while (!errorCount() && peek().startswith(":")) {
    StringRef tok = next();
    phdrs.push_back((tok.size() == 1) ? next() : tok.substr(1));
  }
  return phdrs;
}

// Read a program header type name. The next token must be a
// name of a program header type or a constant (e.g. "0x3").
unsigned ScriptParser::readPhdrType() {
  StringRef tok = next();
  if (Optional<uint64_t> val = parseInt(tok))
    return *val;

  unsigned ret = StringSwitch<unsigned>(tok)
                     .Case("PT_NULL", PT_NULL)
                     .Case("PT_LOAD", PT_LOAD)
                     .Case("PT_DYNAMIC", PT_DYNAMIC)
                     .Case("PT_INTERP", PT_INTERP)
                     .Case("PT_NOTE", PT_NOTE)
                     .Case("PT_SHLIB", PT_SHLIB)
                     .Case("PT_PHDR", PT_PHDR)
                     .Case("PT_TLS", PT_TLS)
                     .Case("PT_GNU_EH_FRAME", PT_GNU_EH_FRAME)
                     .Case("PT_GNU_STACK", PT_GNU_STACK)
                     .Case("PT_GNU_RELRO", PT_GNU_RELRO)
                     .Case("PT_OPENBSD_RANDOMIZE", PT_OPENBSD_RANDOMIZE)
                     .Case("PT_OPENBSD_WXNEEDED", PT_OPENBSD_WXNEEDED)
                     .Case("PT_OPENBSD_BOOTDATA", PT_OPENBSD_BOOTDATA)
                     .Default(-1);

  if (ret == (unsigned)-1) {
    setError("invalid program header type: " + tok);
    return PT_NULL;
  }
  return ret;
}

// Reads an anonymous version declaration.
void ScriptParser::readAnonymousDeclaration() {
  std::vector<SymbolVersion> locals;
  std::vector<SymbolVersion> globals;
  std::tie(locals, globals) = readSymbols();
//  for (const SymbolVersion &pat : locals)
 //   ; // TODO config->versionDefinitions[VER_NDX_LOCAL].patterns.push_back(pat);
  //for (const SymbolVersion &pat : globals)
 //   ; // TODO
      // config->versionDefinitions[VER_NDX_GLOBAL].patterns.push_back(pat);

  expect(";");
}

// Reads a non-anonymous version definition,
// e.g. "VerStr { global: foo; bar; local: *; };".
void ScriptParser::readVersionDeclaration(StringRef verStr) {
  // Read a symbol list.
  std::vector<SymbolVersion> locals;
  std::vector<SymbolVersion> globals;
  std::tie(locals, globals) = readSymbols();
//  for (const SymbolVersion &pat : locals)
 //   ; // TODO VersionDefinition or delete it and use SymbolVersion

  // Each version may have a parent version. For example, "Ver2"
  // defined as "Ver2 { global: foo; local: *; } Ver1;" has "Ver1"
  // as a parent. This version hierarchy is, probably against your
  // instinct, purely for hint; the runtime doesn't care about it
  // at all. In LLD, we simply ignore it.
  if (peek() != ";")
    skip();
  expect(";");
}

static bool hasWildcard(StringRef s) {
  return s.find_first_of("?*[") != StringRef::npos;
}

// Reads a list of symbols, e.g. "{ global: foo; bar; local: *; };".
std::pair<std::vector<SymbolVersion>, std::vector<SymbolVersion>>
ScriptParser::readSymbols() {
  std::vector<SymbolVersion> locals;
  std::vector<SymbolVersion> globals;
  std::vector<SymbolVersion> *v = &globals;

  while (!errorCount()) {
    if (consume("}"))
      break;
    if (consumeLabel("local")) {
      v = &locals;
      continue;
    }
    if (consumeLabel("global")) {
      v = &globals;
      continue;
    }

    if (consume("extern")) {
      std::vector<SymbolVersion> ext = readVersionExtern();
      v->insert(v->end(), ext.begin(), ext.end());
    } else {
      StringRef tok = next();
      v->push_back({unquote(tok), false, hasWildcard(tok)});
    }
    expect(";");
  }
  return {locals, globals};
}

// Reads an "extern C++" directive, e.g.,
// "extern "C++" { ns::*; "f(int, double)"; };"
//
// The last semicolon is optional. E.g. this is OK:
// "extern "C++" { ns::*; "f(int, double)" };"
std::vector<SymbolVersion> ScriptParser::readVersionExtern() {
  StringRef tok = next();
  bool isCXX = tok == "\"C++\"";
  if (!isCXX && tok != "\"C\"")
    setError("Unknown language");
  expect("{");

  std::vector<SymbolVersion> ret;
  while (!errorCount() && peek() != "}") {
    StringRef tok = next();
    ret.push_back(
        {unquote(tok), isCXX, !tok.startswith("\"") && hasWildcard(tok)});
    if (consume("}"))
      return ret;
    expect(";");
  }

  expect("}");
  return ret;
}

Expr ScriptParser::readMemoryAssignment(StringRef s1, StringRef s2,
                                        StringRef s3) {
  if (!consume(s1) && !consume(s2) && !consume(s3)) {
    setError("expected one of: " + s1 + ", " + s2 + ", or " + s3);
    return Expr();
  }
  expect("=");
  return readExpr();
}

// Parse the MEMORY command as specified in:
// https://sourceware.org/binutils/docs/ld/MEMORY.html
//
// MEMORY { name [(attr)] : ORIGIN = origin, LENGTH = len ... }
void ScriptParser::readMemory() {
  expect("{");
  while (!errorCount() && !consume("}")) {
    StringRef tok = next();
    if (tok == "INCLUDE") {
      readInclude();
      continue;
    }

    uint32_t flags = 0;
    uint32_t negFlags = 0;
    if (consume("(")) {
      std::tie(flags, negFlags) = readMemoryAttributes();
      expect(")");
    }
    expect(":");

    Expr origin = readMemoryAssignment("ORIGIN", "org", "o");
    expect(",");
    Expr length = readMemoryAssignment("LENGTH", "len", "l");

    // Add the memory region to the region map.
    MemoryRegion *mr = make<MemoryRegion>(tok, origin, length, flags, negFlags);
    if (!memoryRegions.insert({tok, mr}).second)
      setError("region '" + tok + "' already defined");
  }
}

// This function parses the attributes used to match against section
// flags when placing output sections in a memory region. These flags
// are only used when an explicit memory region name is not used.
std::pair<uint32_t, uint32_t> ScriptParser::readMemoryAttributes() {
  uint32_t flags = 0;
  uint32_t negFlags = 0;
  bool invert = false;

  for (char c : next().lower()) {
    uint32_t flag = 0;
    if (c == '!')
      invert = !invert;
    else if (c == 'w')
      flag = SHF_WRITE;
    else if (c == 'x')
      flag = SHF_EXECINSTR;
    else if (c == 'a')
      flag = SHF_ALLOC;
    else if (c != 'r')
      setError("invalid memory region attribute");

    if (invert)
      negFlags |= flag;
    else
      flags |= flag;
  }
  return {flags, negFlags};
}

void readLinkerScript(MemoryBufferRef mb) {
  ScriptParser(mb).readLinkerScript();
}

void readVersionScript(MemoryBufferRef mb) {
  ScriptParser(mb).readVersionScript();
}

void readDynamicList(MemoryBufferRef mb) { ScriptParser(mb).readDynamicList(); }

void readDefsym(StringRef name, MemoryBufferRef mb) {
  ScriptParser(mb).readDefsym(name);
}

int main(int argc, char *argv[]) {
  if (argc < 2)
    return 1;
  auto mb = readFile(argv[1]);
  readLinkerScript(*mb);
  return 0;
}