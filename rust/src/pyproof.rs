//! Proof that a Python script is read-only: the only effects it can have are reading local files, reading the process
//! arguments, printing, and HTTP GET/HEAD requests. [`read_only`] returns `true` only for a script it can prove
//! this for; every parse error, unknown syntax node, unlisted import or doubtful call returns `false`.
//!
//! The script is parsed with tree-sitter (a C parser: linear time, no recursion, error tolerant). Every named syntax
//! node must be on a list, so syntax added to the grammar later is rejected until someone classifies it. Name rules
//! hold for attribute names and bare names alike, so `getattr`-free aliasing (`f = os.remove`) is rejected too.

use std::ops::ControlFlow;
use std::time::{Duration, Instant};
use tree_sitter::{Node, ParseOptions, Parser};

/// Larger scripts are not proven (the work is linear, this bounds it).
const MAX_SOURCE: usize = 256 * 1024;
/// Syntax-tree nesting limit. The walker is iterative, so this only rejects absurd input.
const MAX_DEPTH: usize = 256;
/// Parsing gives up (not proven) after this long.
const MAX_PARSE: Duration = Duration::from_secs(1);

/// Top-level modules (and the submodules below) a proven script may import. `requests` and `httpx` are allowed because
/// their calls are restricted to GET/HEAD/OPTIONS; `__future__` because `from __future__ import annotations` is common.
const MODULES: &[&str] = &[
    "json",
    "re",
    "sys",
    "os",
    "pathlib",
    "datetime",
    "time",
    "collections",
    "itertools",
    "csv",
    "textwrap",
    "math",
    "statistics",
    "hashlib",
    "base64",
    "urllib",
    "ssl",
    "typing",
    "functools",
    "argparse",
    "string",
    "shlex",
    "glob",
    "fnmatch",
    "ast",
    "tokenize",
    "difflib",
    "sqlite3",
    "yaml",
    "html",
    "zlib",
    "gzip",
    "operator",
    "pprint",
    "logging",
    "unicodedata",
    "io",
    "copy",
    "enum",
    "dataclasses",
    "uuid",
    "random",
    "tomllib",
    "stat",
    "zoneinfo",
    "decimal",
    "fractions",
    "heapq",
    "bisect",
    "requests",
    "httpx",
    "__future__",
    // Submodules. `xml` and `xml.etree` are packages: only the submodule can be imported from them (see PACKAGES).
    "urllib.request",
    "urllib.parse",
    "urllib.error",
    "os.path",
    "collections.abc",
    "xml",
    "xml.etree",
    "xml.etree.ElementTree",
];
/// Packages that hold no names of their own: `from urllib import request` is fine, `from urllib import anything_else` is not.
const PACKAGES: &[&str] = &["urllib", "xml", "xml.etree"];

/// The only `os` attributes a proven script may touch. Everything else (environ, system, remove, open, ...) is rejected.
const OS_ALLOWED: &[&str] = &[
    "path",
    "getcwd",
    "getcwdb",
    "listdir",
    "walk",
    "scandir",
    "stat",
    "lstat",
    "sep",
    "linesep",
    "name",
    "pathsep",
    "curdir",
    "pardir",
    "extsep",
    "altsep",
    "devnull",
    "getpid",
    "getppid",
    "cpu_count",
    "uname",
    "access",
    "readlink",
    "fspath",
    "fsencode",
    "fsdecode",
    "get_terminal_size",
    "terminal_size",
    "R_OK",
    "W_OK",
    "X_OK",
    "F_OK",
    "getlogin",
    "urandom",
    "strerror",
    "error",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "times",
    "stat_result",
    "DirEntry",
    "PathLike",
    "chdir",
    "getloadavg",
    "statvfs",
    "isatty",
];
/// The only `sys` attributes a proven script may touch (no `modules`, hooks or tracing).
const SYS_ALLOWED: &[&str] = &[
    "argv",
    "stdout",
    "stderr",
    "stdin",
    "exit",
    "version",
    "version_info",
    "platform",
    "path",
    "maxsize",
    "getdefaultencoding",
    "getfilesystemencoding",
    "getrecursionlimit",
    "byteorder",
    "executable",
    "getsizeof",
    "float_info",
    "hexversion",
    "implementation",
    "exc_info",
    "maxunicode",
    "intern",
];
/// `yaml` entry points that can construct arbitrary Python objects (code execution from the data being parsed).
const YAML_DENIED: &[&str] = &[
    "load",
    "load_all",
    "unsafe_load",
    "unsafe_load_all",
    "full_load",
    "full_load_all",
    "Loader",
    "UnsafeLoader",
    "FullLoader",
    "add_constructor",
    "add_multi_constructor",
    "loader",
    "constructor",
];
/// Dunder names that are harmless. Any other `__x__` (`__import__`, `__builtins__`, `__class__`, `__globals__`, ...) is
/// a way out of the name rules, so it is rejected.
const DUNDERS: &[&str] = &[
    "__name__",
    "__file__",
    "__doc__",
    "__init__",
    "__str__",
    "__repr__",
    "__len__",
    "__iter__",
    "__next__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__hash__",
    "__enter__",
    "__exit__",
    "__call__",
    "__post_init__",
    "__getitem__",
    "__contains__",
    "__version__",
    "__bool__",
    "__add__",
    "__sub__",
    "__mul__",
    "__slots__",
    "__all__",
];
/// Names rejected wherever they appear, as a bare name or an attribute: mutators of files, processes and the
/// environment, network writes, dynamic code, and file-opening classes. `write`, `writelines` and `replace` are
/// rejected too except for `sys.stdout.write` and `str.replace` (see `check_identifier`).
const DENIED: &[&str] = &[
    "write_text",
    "write_bytes",
    "touch",
    "unlink",
    "rmdir",
    "rmtree",
    "removedirs",
    "rename",
    "renames",
    "mkdir",
    "makedirs",
    "mkdtemp",
    "mkstemp",
    "mktemp",
    "chmod",
    "chown",
    "lchown",
    "lchmod",
    "fchmod",
    "symlink",
    "symlink_to",
    "hardlink_to",
    "link",
    "link_to",
    "truncate",
    "ftruncate",
    "utime",
    "system",
    "popen",
    "Popen",
    "check_output",
    "check_call",
    "getoutput",
    "getstatusoutput",
    "kill",
    "killpg",
    "putenv",
    "unsetenv",
    "fork",
    "forkpty",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "posix_spawn",
    "posix_spawnp",
    "startfile",
    "environ",
    "environb",
    "getenv",
    "getenvb",
    "expandvars",
    "getpass",
    "keyring",
    "write",
    "writelines",
    "replace",
    "post",
    "put",
    "patch",
    "delete",
    "urlretrieve",
    "retrieve",
    "URLopener",
    "FancyURLopener",
    "FileIO",
    "FileType",
    "FileHandler",
    "WatchedFileHandler",
    "RotatingFileHandler",
    "TimedRotatingFileHandler",
    "HTTPHandler",
    "SocketHandler",
    "DatagramHandler",
    "SMTPHandler",
    "SysLogHandler",
    "handlers",
    "load_extension",
    "enable_load_extension",
    "send",
    "sendall",
    "sendto",
    "sendmsg",
    "get_method",
    "methodcaller",
    "attrgetter",
    "eval",
    "exec",
    "execfile",
    "import_module",
    "GzipFile",
    "BZ2File",
    "fdopen",
    "dup2",
    "open_code",
    "putrequest",
    "fileConfig",
    "dictConfig",
    // Decoders and decompressors: decoding an embedded blob is how a payload hides from a static check, so a script
    // that decodes anything is left to the model. (`bytes.decode` is plain text decoding and stays allowed.)
    "b64decode",
    "standard_b64decode",
    "urlsafe_b64decode",
    "decodebytes",
    "decodestring",
    "a85decode",
    "b85decode",
    "b32decode",
    "b32hexdecode",
    "b16decode",
    "a2b_base64",
    "a2b_hex",
    "a2b_uu",
    "a2b_qp",
    "a2b_hqx",
    "a2b_ascii",
    "unhexlify",
    "fromhex",
    "decompress",
    "decompressobj",
    "uudecode",
];
/// Names rejected as bare names only (as attributes they are harmless: `args.input`, `re.compile`).
const DENIED_BARE: &[&str] = &["input", "raw_input", "compile", "breakpoint"];
/// Names that may only appear as the callee of a call, and every such call is checked in `check_call`.
const CALLEES: &[&str] = &[
    "open",
    "getattr",
    "setattr",
    "delattr",
    "vars",
    "globals",
    "locals",
    "Request",
    "urlopen",
    "connect",
    "request",
    "stream",
    "print",
    "basicConfig",
];
/// Attributes whose assignment can turn a `Request` into a POST or change its method.
const ASSIGN_DENIED: &[&str] = &["data", "method", "get_method"];
/// Attribute names that reach a module a proven script may not import (`urllib.request.os.remove`, `glob.os`,
/// `logging.sys.modules`). Imports of these names are rejected too.
const ESCAPES: &[&str] = &[
    "os",
    "sys",
    "_os",
    "_sys",
    "posix",
    "nt",
    "subprocess",
    "shutil",
    "socket",
    "builtins",
    "importlib",
    "ctypes",
    "tempfile",
    "http",
    "ftplib",
    "smtplib",
    "threading",
    "multiprocessing",
    "asyncio",
    "pickle",
    "marshal",
    "signal",
    "pty",
];

/// Secret path fragments, matched anywhere in a string literal, ASCII case-insensitive.
const SECRET_FRAGMENTS: &[&str] = &[
    ".ssh",
    ".aws",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pypirc",
    ".kube/config",
    ".gnupg",
    ".docker/config",
    "/etc/shadow",
    ".git-credentials",
    "/environ",
];
/// Secret file suffixes that must end at a word boundary (`.env` and `.env.local` match, `.environ` and `.keys` do not).
const SECRET_WORDS: &[&str] = &[".env", ".pem", ".key"];

/// Whether `source` is proven read-only. `false` means "not proven", never "known to write".
#[must_use]
pub fn read_only(source: &str) -> bool {
    if source.len() > MAX_SOURCE || source.contains('\0') {
        return false;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let start = Instant::now();
    let mut progress = |_: &tree_sitter::ParseState| {
        if start.elapsed() > MAX_PARSE {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let Some(tree) = parser.parse_with_options(
        &mut |at, _| source.as_bytes().get(at..).unwrap_or_default(),
        None,
        Some(ParseOptions::new().progress_callback(&mut progress)),
    ) else {
        return false;
    };
    let root = tree.root_node();
    if root.has_error() {
        return false;
    }
    let mut proof = Proof::new(source);
    proof.collect_imports(root) && proof.check(root)
}

enum Step {
    Go,
    Skip,
    Stop,
}

/// Pre-order walk of the named nodes under `root`. Returns `false` when `f` stops it or the tree is too deep.
fn walk<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>) -> Step) -> bool {
    let mut cursor = root.walk();
    let mut depth = 0usize;
    loop {
        let node = cursor.node();
        let step = if node.is_named() { f(node) } else { Step::Go };
        match step {
            Step::Stop => return false,
            Step::Go if cursor.goto_first_child() => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return false;
                }
                continue;
            }
            _ => {}
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if depth == 0 || !cursor.goto_parent() {
                return true;
            }
            depth -= 1;
        }
    }
}

fn named_children(node: Node) -> Vec<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn step(ok: bool) -> Step {
    if ok {
        Step::Go
    } else {
        Step::Stop
    }
}

fn dunder_rejected(name: &str) -> bool {
    name.len() > 4 && name.starts_with("__") && name.ends_with("__") && !DUNDERS.contains(&name)
}

fn name_banned(name: &str) -> bool {
    DENIED.contains(&name) || DENIED_BARE.contains(&name) || dunder_rejected(name)
}

fn module_ok(module: &str) -> bool {
    MODULES.contains(&module)
}

fn has_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if SECRET_FRAGMENTS.iter().any(|f| lower.contains(f)) {
        return true;
    }
    SECRET_WORDS.iter().any(|word| {
        lower.match_indices(word).any(|(at, _)| {
            !lower
                .as_bytes()
                .get(at + word.len())
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        })
    })
}

/// SQL a read-only connection could still use to write a file somewhere else.
fn writes_other_file(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["attach", "vacuum", "load_extension"]
        .iter()
        .any(|w| lower.contains(w))
}

fn read_mode(mode: &str) -> bool {
    !mode.contains(['w', 'a', 'x', '+'])
}

fn mode_shaped(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| "rwaxbtU+".contains(c))
}

/// `mode=ro` as a query parameter of a `file:` URI.
fn uri_read_only(uri: &str) -> bool {
    // Exactly one `mode`, because SQLite's choice between repeated parameters is not worth relying on.
    let Some((_, query)) = uri.split_once('?') else {
        return false;
    };
    uri.starts_with("file:")
        && query
            .split('&')
            .filter(|p| p.starts_with("mode="))
            .eq(["mode=ro"])
}

fn hides_text_in_escapes(text: &str) -> bool {
    text.as_bytes()
        .windows(2)
        .any(|w| w[0] == b'\\' && matches!(w[1], b'x' | b'u' | b'U' | b'N' | b'0'..=b'7'))
}

struct Args<'t, 's> {
    pos: Vec<Node<'t>>,
    kws: Vec<(&'s str, Node<'t>)>,
    pos_splat: bool,
    kw_splat: bool,
}

struct Proof<'s> {
    src: &'s str,
    /// Names bound to `os`, `sys` and `yaml`: used only as `name.attribute`, with the attribute checked.
    guarded: Vec<&'s str>,
    os: Vec<&'s str>,
    sys: Vec<&'s str>,
    yaml: Vec<&'s str>,
    /// Names bound to `base64`: `base64.decode` is a decoder, unlike `bytes.decode`.
    base64: Vec<&'s str>,
    /// Names bound to any imported module (`gzip.open(path)` takes a path, not a mode).
    modules: Vec<&'s str>,
    sqlite: bool,
}

impl<'s> Proof<'s> {
    fn new(src: &'s str) -> Self {
        Proof {
            src,
            guarded: vec![],
            os: vec![],
            sys: vec![],
            yaml: vec![],
            base64: vec![],
            modules: vec![],
            sqlite: false,
        }
    }

    fn t(&self, node: Node) -> &'s str {
        self.src
            .get(node.start_byte()..node.end_byte())
            .unwrap_or("")
    }

    /// Text of a dotted name without the whitespace Python allows inside it.
    fn dotted(&self, node: Node) -> String {
        self.t(node)
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '\\')
            .collect()
    }

    /// The value of a plain string literal (no f-string, no escapes, no bytes), else `None`.
    fn plain_str(&self, node: Node) -> Option<&'s str> {
        if node.kind() != "string" {
            return None;
        }
        let mut cursor = node.walk();
        let kids: Vec<Node> = node.children(&mut cursor).collect();
        let (first, last) = (kids.first()?, kids.last()?);
        let prefix = self.t(*first).trim_end_matches(['"', '\'']);
        if kids.len() < 2 || !prefix.chars().all(|c| "rRuU".contains(c)) {
            return None;
        }
        if kids[1..kids.len() - 1]
            .iter()
            .any(|k| k.kind() != "string_content")
        {
            return None;
        }
        self.src.get(first.end_byte()..last.start_byte())
    }

    fn args<'t>(&self, call: Node<'t>) -> Option<Args<'t, 's>> {
        let list = call.child_by_field_name("arguments")?;
        let mut args = Args {
            pos: vec![],
            kws: vec![],
            pos_splat: false,
            kw_splat: false,
        };
        if list.kind() != "argument_list" {
            args.pos.push(list);
            return Some(args);
        }
        let mut cursor = list.walk();
        for arg in list.named_children(&mut cursor) {
            match arg.kind() {
                "comment" => {}
                "keyword_argument" => {
                    let name = arg.child_by_field_name("name")?;
                    let value = arg.child_by_field_name("value")?;
                    args.kws.push((self.t(name), value));
                }
                "list_splat" | "parenthesized_list_splat" => args.pos_splat = true,
                "dictionary_splat" => args.kw_splat = true,
                _ => args.pos.push(arg),
            }
        }
        Some(args)
    }

    // ---- imports ------------------------------------------------------------------------------------------------

    fn collect_imports(&mut self, root: Node) -> bool {
        walk(root, |n| match n.kind() {
            "import_statement" => step(self.import_plain(n)),
            "import_from_statement" => step(self.import_from(n)),
            // `from __future__ import ...` only switches compiler features.
            "future_import_statement" => Step::Skip,
            _ => Step::Go,
        })
    }

    fn import_plain(&mut self, node: Node) -> bool {
        let mut cursor = node.walk();
        for item in node.children_by_field_name("name", &mut cursor) {
            let ok = match item.kind() {
                // `import a.b.c` binds `a`.
                "dotted_name" => match item.named_child(0) {
                    Some(top) => self.bind_module(&self.dotted(item), self.t(top), self.t(top)),
                    None => false,
                },
                // `import a.b.c as d` binds `d` to the submodule.
                "aliased_import" => match (
                    item.child_by_field_name("name"),
                    item.child_by_field_name("alias"),
                ) {
                    (Some(name), Some(alias)) => {
                        let full = self.dotted(name);
                        self.bind_module(&full, self.t(alias), &full)
                    }
                    _ => false,
                },
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }

    /// `full` is the imported module, `bound` the name it is bound to and `bound_module` what that name refers to.
    fn bind_module(&mut self, full: &str, bound: &'s str, bound_module: &str) -> bool {
        if !module_ok(full) || name_banned(bound) {
            return false;
        }
        match bound_module {
            "os" => {
                self.os.push(bound);
                self.guarded.push(bound);
            }
            "sys" => {
                self.sys.push(bound);
                self.guarded.push(bound);
            }
            "yaml" => {
                self.yaml.push(bound);
                self.guarded.push(bound);
            }
            "base64" => self.base64.push(bound),
            _ => {}
        }
        self.sqlite |= full == "sqlite3";
        self.modules.push(bound);
        true
    }

    fn import_from(&mut self, node: Node) -> bool {
        let Some(module_node) = node.child_by_field_name("module_name") else {
            return false;
        };
        if module_node.kind() != "dotted_name" {
            return false; // relative import
        }
        let module = self.dotted(module_node);
        if !module_ok(&module) {
            return false;
        }
        self.sqlite |= module == "sqlite3";
        let mut cursor = node.walk();
        let items: Vec<Node> = node.children_by_field_name("name", &mut cursor).collect();
        if items.is_empty() {
            return false; // wildcard
        }
        items.into_iter().all(|item| {
            let (name, alias) = match item.kind() {
                "dotted_name" => (item, None),
                "aliased_import" => match (
                    item.child_by_field_name("name"),
                    item.child_by_field_name("alias"),
                ) {
                    (Some(name), Some(alias)) => (name, Some(alias)),
                    _ => return false,
                },
                _ => return false,
            };
            let (name, bound) = (
                self.t(name),
                alias.map_or_else(|| self.t(name), |a| self.t(a)),
            );
            self.import_name(&module, name, bound)
        })
    }

    fn import_name(&mut self, module: &str, name: &'s str, bound: &'s str) -> bool {
        if name.contains('.')
            || name_banned(name)
            || name_banned(bound)
            || ESCAPES.contains(&name)
            || ESCAPES.contains(&bound)
        {
            return false;
        }
        // Renaming a restricted callee would hide it from the call checks.
        if name != bound && (CALLEES.contains(&name) || CALLEES.contains(&bound)) {
            return false;
        }
        if module_ok(&format!("{module}.{name}")) {
            self.modules.push(bound);
            return true;
        }
        if PACKAGES.contains(&module) {
            return false;
        }
        match module {
            "os" => OS_ALLOWED.contains(&name),
            "sys" => SYS_ALLOWED.contains(&name),
            "yaml" => !YAML_DENIED.contains(&name),
            "base64" => name != "decode",
            _ => true,
        }
    }

    // ---- the walk -----------------------------------------------------------------------------------------------

    fn check(&self, root: Node) -> bool {
        walk(root, |n| match n.kind() {
            // Already validated by `collect_imports`; their identifiers are not uses.
            "import_statement" | "import_from_statement" | "future_import_statement" => Step::Skip,
            "identifier" => step(self.check_identifier(n)),
            "attribute" => step(self.check_attribute(n)),
            "call" => step(self.check_call(n)),
            "string" | "concatenated_string" => step(self.check_string(n)),
            "delete_statement" => step(self.check_delete(n)),
            kind if ALLOWED_NODES.contains(&kind) => Step::Go,
            _ => Step::Stop,
        })
    }

    fn check_string(&self, node: Node) -> bool {
        let text = self.t(node);
        // Adjacent literals ("~/.s" "sh") are one string at run time.
        let joined: String;
        let text = if node.kind() == "concatenated_string" {
            joined = text
                .chars()
                .filter(|c| !c.is_whitespace() && !"\"'\\".contains(*c))
                .collect();
            &joined
        } else {
            text
        };
        // `\x2essh` spells `.ssh`: strings that hide characters behind escapes are not read.
        let raw = text
            .bytes()
            .take_while(u8::is_ascii_alphabetic)
            .any(|b| b | 0x20 == b'r');
        if node.kind() == "string" && !raw && hides_text_in_escapes(text) {
            return false;
        }
        !(has_secret(text) || self.sqlite && writes_other_file(text))
    }

    fn check_delete(&self, node: Node) -> bool {
        named_children(node).iter().all(|c| match c.kind() {
            "identifier" | "comment" => true,
            "expression_list" => named_children(*c)
                .iter()
                .all(|i| matches!(i.kind(), "identifier" | "comment")),
            _ => false,
        })
    }

    fn check_identifier(&self, node: Node) -> bool {
        let name = self.t(node);
        // Python folds identifiers to NFKC, so a full-width `eval` is `eval`.
        if !name.is_ascii() || dunder_rejected(name) {
            return false;
        }
        let Some(parent) = node.parent() else {
            return true;
        };
        let field_is = |p: Node, field: &str| {
            p.child_by_field_name(field)
                .is_some_and(|c| c.id() == node.id())
        };
        if parent.kind() == "keyword_argument" && field_is(parent, "name") {
            return true; // `stream=True`, `input=x`: a parameter name, not a use
        }
        let is_attr = parent.kind() == "attribute" && field_is(parent, "attribute");
        if (is_attr && ESCAPES.contains(&name))
            || DENIED.contains(&name) && !(is_attr && self.allowed_denied(name, parent))
        {
            return false;
        }
        if !is_attr && DENIED_BARE.contains(&name) {
            return false;
        }
        let expr = if is_attr { parent } else { node };
        if CALLEES.contains(&name) {
            let called = expr.parent().is_some_and(|call| {
                call.kind() == "call"
                    && call
                        .child_by_field_name("function")
                        .is_some_and(|f| f.id() == expr.id())
            });
            // `urllib.request.urlopen`: a module path, not a call of `request`.
            let namespace = matches!(name, "request" | "stream")
                && expr.parent().is_some_and(|p| {
                    p.kind() == "attribute"
                        && p.child_by_field_name("object")
                            .is_some_and(|o| o.id() == expr.id())
                });
            if !called && !namespace {
                return false;
            }
        }
        if !is_attr && self.guarded.contains(&name) {
            // A module that is passed around could be called as anything.
            let receiver = parent.kind() == "attribute" && field_is(parent, "object");
            if !receiver {
                return false;
            }
        }
        true
    }

    /// The uses of `write`, `writelines` and `replace` that are not file writes.
    fn allowed_denied(&self, name: &str, attribute: Node) -> bool {
        match name {
            "write" | "writelines" => {
                let receiver = attribute
                    .child_by_field_name("object")
                    .map_or("", |o| self.t(o));
                receiver == "sys.stdout" || receiver == "sys.stderr"
            }
            // `str.replace(old, new)` takes two arguments; `Path.replace(target)` and `os.replace` rename files.
            "replace" => attribute.parent().is_some_and(|call| {
                call.kind() == "call"
                    && call
                        .child_by_field_name("function")
                        .is_some_and(|f| f.id() == attribute.id())
                    && self.args(call).is_some_and(|a| {
                        a.pos.len() + a.kws.len() >= 2 && !a.pos_splat && !a.kw_splat
                    })
                    && self.receiver_is_not_os(attribute)
            }),
            _ => false,
        }
    }

    fn receiver_is_not_os(&self, attribute: Node) -> bool {
        attribute
            .child_by_field_name("object")
            .is_none_or(|o| o.kind() != "identifier" || !self.os.contains(&self.t(o)))
    }

    fn check_attribute(&self, node: Node) -> bool {
        let (Some(object), Some(attr)) = (
            node.child_by_field_name("object"),
            node.child_by_field_name("attribute"),
        ) else {
            return false;
        };
        let attr = self.t(attr);
        if object.kind() == "identifier" {
            let base = self.t(object);
            if self.os.contains(&base) && !OS_ALLOWED.contains(&attr) {
                return false;
            }
            if self.sys.contains(&base) && !SYS_ALLOWED.contains(&attr) {
                return false;
            }
            if self.yaml.contains(&base) && YAML_DENIED.contains(&attr) {
                return false;
            }
            // `base64.decode(input, output)` decodes a stream; `.decode()` on bytes is ordinary text decoding.
            if self.base64.contains(&base) && attr == "decode" {
                return false;
            }
        }
        !(ASSIGN_DENIED.contains(&attr) && is_store(node))
    }

    // ---- calls --------------------------------------------------------------------------------------------------

    fn check_call(&self, call: Node) -> bool {
        let Some(func) = call.child_by_field_name("function") else {
            return false;
        };
        let name = match func.kind() {
            "identifier" => self.t(func),
            "attribute" => func
                .child_by_field_name("attribute")
                .map_or("", |a| self.t(a)),
            _ => return true,
        };
        if !CALLEES.contains(&name) {
            return true;
        }
        let Some(args) = self.args(call) else {
            return false;
        };
        if name != "print" && (args.pos_splat || args.kw_splat) {
            return false;
        }
        let kw = |key: &str| args.kws.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        let method_is = |node: Node, allowed: &[&str]| {
            self.plain_str(node)
                .is_some_and(|m| allowed.iter().any(|a| m.eq_ignore_ascii_case(a)))
        };
        match name {
            "open" => self.check_open(func, &args),
            "getattr" | "setattr" | "delattr" => {
                let count = match name {
                    "getattr" => 2..=3,
                    "setattr" => 3..=3,
                    _ => 2..=2,
                };
                let literal = args.pos.get(1).and_then(|n| self.plain_str(*n));
                args.kws.is_empty()
                    && count.contains(&args.pos.len())
                    && literal.is_some_and(|l| {
                        let writable = name != "getattr" && ASSIGN_DENIED.contains(&l);
                        !(name_banned(l) || writable || CALLEES.contains(&l))
                    })
            }
            // vars(x) hands out x.__dict__, which a script can write through (`vars(req)['data'] = ...`).
            "vars" | "globals" | "locals" => false,
            "Request" => {
                args.pos.len() <= 1
                    && kw("data").is_none()
                    && kw("method").is_none_or(|m| method_is(m, &["GET", "HEAD"]))
            }
            "urlopen" => args.pos.len() <= 1 && kw("data").is_none(),
            "connect" => self.check_connect(&args),
            "request" | "stream" => kw("method")
                .or_else(|| args.pos.first().copied())
                .is_some_and(|m| method_is(m, &["get", "head", "options"])),
            "print" => {
                !args.kw_splat
                    && kw("file").is_none_or(|f| matches!(self.t(f), "sys.stdout" | "sys.stderr"))
            }
            "basicConfig" => kw("filename").is_none() && kw("filemode").is_none(),
            _ => false,
        }
    }

    /// `sqlite3.connect`: an in-memory database or a literal `file:` URI with `mode=ro` and `uri=True`.
    fn check_connect(&self, args: &Args<'_, 's>) -> bool {
        let Some(target) = args.pos.first().and_then(|n| self.plain_str(*n)) else {
            return false;
        };
        let uri = args
            .kws
            .iter()
            .any(|(k, v)| *k == "uri" && self.t(*v) == "True");
        target == ":memory:" || (uri && uri_read_only(target))
    }

    fn check_open(&self, func: Node, args: &Args<'_, 's>) -> bool {
        if args
            .kws
            .iter()
            .any(|(k, _)| matches!(*k, "opener" | "data"))
        {
            return false;
        }
        let reads = |node: Node| self.plain_str(node).is_some_and(read_mode);
        if args.kws.iter().any(|(k, v)| *k == "mode" && !reads(*v)) {
            return false;
        }
        if func.kind() == "identifier" {
            // open(file, mode, ...)
            return args.pos.get(1).is_none_or(|m| reads(*m));
        }
        // `.open(...)`: `Path.open(mode)` takes the mode first, `gzip.open(path, mode)` takes it second.
        if !args.pos.iter().skip(1).all(|m| reads(*m)) {
            return false;
        }
        let on_module = func
            .child_by_field_name("object")
            .is_some_and(|o| o.kind() == "identifier" && self.modules.contains(&self.t(o)));
        match args.pos.first() {
            None => true,
            Some(first) => match self.plain_str(*first) {
                Some(text) => !mode_shaped(text) || read_mode(text),
                None => on_module,
            },
        }
    }
}

/// An attribute that is being assigned to, deleted, or bound as a loop or `as` target.
fn is_store(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let is_left = || {
        parent
            .child_by_field_name("left")
            .is_some_and(|l| l.id() == node.id())
    };
    match parent.kind() {
        "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => is_left(),
        "pattern_list" | "tuple_pattern" | "list_pattern" | "list_splat_pattern" | "as_pattern"
        | "as_pattern_target" | "with_item" | "delete_statement" => true,
        _ => false,
    }
}

/// Every named node kind a proven script may contain. `exec_statement`, `print_statement` and `chevron` (Python 2
/// syntax) and anything the grammar adds later are rejected.
const ALLOWED_NODES: &[&str] = &[
    "aliased_import",
    "argument_list",
    "as_pattern",
    "as_pattern_target",
    "assert_statement",
    "assignment",
    "augmented_assignment",
    "await",
    "binary_operator",
    "block",
    "boolean_operator",
    "break_statement",
    "case_clause",
    "case_pattern",
    "class_definition",
    "class_pattern",
    "comment",
    "comparison_operator",
    "complex_pattern",
    "conditional_expression",
    "constrained_type",
    "continue_statement",
    "decorated_definition",
    "decorator",
    "dict_pattern",
    "default_parameter",
    "dictionary",
    "dictionary_comprehension",
    "dictionary_splat",
    "dictionary_splat_pattern",
    "dotted_name",
    "elif_clause",
    "else_clause",
    "escape_interpolation",
    "escape_sequence",
    "except_clause",
    "expression_list",
    "expression_statement",
    "false",
    "finally_clause",
    "float",
    "for_in_clause",
    "for_statement",
    "format_expression",
    "format_specifier",
    "function_definition",
    "generator_expression",
    "generic_type",
    "global_statement",
    "if_clause",
    "if_statement",
    "integer",
    "interpolation",
    "keyword_argument",
    "keyword_pattern",
    "keyword_separator",
    "lambda",
    "lambda_parameters",
    "line_continuation",
    "list",
    "list_comprehension",
    "list_pattern",
    "list_splat",
    "list_splat_pattern",
    "match_statement",
    "member_type",
    "module",
    "named_expression",
    "none",
    "nonlocal_statement",
    "not_operator",
    "pair",
    "parameter",
    "parameters",
    "parenthesized_expression",
    "parenthesized_list_splat",
    "pass_statement",
    "pattern_list",
    "positional_separator",
    "raise_statement",
    "return_statement",
    "set",
    "set_comprehension",
    "slice",
    "splat_pattern",
    "splat_type",
    "string_content",
    "string_end",
    "string_start",
    "subscript",
    "true",
    "try_statement",
    "tuple",
    "tuple_pattern",
    "type",
    "type_alias_statement",
    "type_conversion",
    "type_parameter",
    "typed_default_parameter",
    "typed_parameter",
    "unary_operator",
    "union_pattern",
    "union_type",
    "while_statement",
    "with_clause",
    "with_item",
    "with_statement",
    "yield",
    "ellipsis",
];

#[cfg(test)]
mod tests {
    use super::read_only;

    const ACCEPT: &[(&str, &str)] = &[
        ("print", "print('hello')"),
        ("json read", "import json\nprint(json.load(open('a.json'))['k'])"),
        ("json read with mode", "import json\nwith open('a.json', 'r', encoding='utf-8') as f:\n    print(json.load(f))"),
        ("binary read", "with open('a.bin', 'rb') as f:\n    print(len(f.read()))"),
        (
            "pathlib read",
            "from pathlib import Path\nfor p in Path('.').rglob('*.py'):\n    print(p, p.read_text().count('x'))",
        ),
        ("Path.open read", "from pathlib import Path\nprint(Path('a').open('r').read())\nprint(Path('a').open().read())"),
        ("glob", "import glob, os\nfor f in glob.glob('*.log'):\n    print(f, os.path.getsize(f), os.getcwd())"),
        ("os listing", "import os\nfor root, dirs, files in os.walk('.'):\n    print(root, os.listdir(root), os.stat(root))"),
        (
            "rg-like scan",
            "import re, sys\nrx = re.compile(sys.argv[1])\nfor path in sys.argv[2:]:\n    for i, line in enumerate(open(path), 1):\n        if rx.search(line):\n            print(f'{path}:{i}:{line.rstrip()}')\n            sys.stdout.write('')",
        ),
        (
            "urllib GET with headers",
            "import json, urllib.request\nreq = urllib.request.Request('http://x/y', headers={'Accept': 'application/json'})\nwith urllib.request.urlopen(req, timeout=10) as r:\n    print(json.loads(r.read().decode()))",
        ),
        ("urlopen plain", "from urllib.request import urlopen\nprint(urlopen('http://x').read())"),
        ("Request method GET", "import urllib.request as u\nu.urlopen(u.Request('http://x', method='get'))"),
        ("Request method HEAD", "import urllib.request as u\nu.urlopen(u.Request('http://x', method='HEAD'))"),
        ("requests get", "import requests\nprint(requests.get('http://x', stream=True, timeout=3).json())"),
        ("requests head", "import requests\nprint(requests.head('http://x').headers)\nprint(requests.request('OPTIONS', 'http://x'))"),
        ("sqlite3 read only", "import sqlite3\nc = sqlite3.connect('file:/tmp/a.db?mode=ro', uri=True)\nprint(c.execute('select 1').fetchall())"),
        ("sqlite3 memory", "import sqlite3\nc = sqlite3.connect(':memory:')\nc.execute('create table t(a)')"),
        (
            "argparse printing",
            "import argparse\np = argparse.ArgumentParser()\np.add_argument('--input')\na = p.parse_args()\nprint(a.input)",
        ),
        ("classes and decorators", "import functools\nclass A:\n    @property\n    def x(self):\n        return 1\n    def __init__(self):\n        super().__init__()\n@functools.lru_cache\ndef f(n):\n    return n\nprint(A().x, f(2))"),
        ("comprehensions and lambda", "print(sorted({k: v for k, v in zip('ab', [1, 2])}, key=lambda k: k), [x * 2 for x in range(3)])"),
        ("str.replace", "print('a-b'.replace('-', '_'))"),
        ("del local", "x = 1\ndel x"),
        ("global write", "n = 0\ndef f():\n    global n\n    n = 1\nf()"),
        ("print to stderr", "import sys\nprint('x', file=sys.stderr)"),
        ("yaml safe", "import yaml\nprint(yaml.safe_load(open('a.yml')))"),
        ("ElementTree", "import xml.etree.ElementTree as ET\nprint(ET.parse('a.xml').getroot().tag)"),
        ("from xml.etree", "from xml.etree import ElementTree\nprint(ElementTree.fromstring('<a/>'))"),
        ("gzip read", "import gzip\nprint(gzip.open('a.gz').read())\nprint(gzip.open('a.gz', 'rt').read())"),
        ("future import", "from __future__ import annotations\nprint(1)"),
        ("match statement", "match 1:\n    case 1:\n        print('one')"),
        ("walrus and fstring", "if (n := len('abc')) > 2:\n    print(f'{n:>4} {n!r}')"),
        ("try and raise", "try:\n    raise ValueError('x')\nexcept ValueError as e:\n    print(e)\nfinally:\n    pass"),
        ("empty", ""),
        ("comment only", "# nothing"),
        ("os module path", "import os as o\nprint(o.path.join('a', 'b'))"),
        ("from os import allowed", "from os import getcwd, path\nprint(getcwd(), path.join('a'))"),
        ("from os.path import", "from os.path import join\nprint(join('a'))"),
        ("from urllib import request", "from urllib import request\nrequest.urlopen('http://x')"),
        ("str.replace chain", "import re\nprint(re.compile('x').sub('a', 'b').replace('c', 'd'))"),
        ("sys.argv and exit", "import sys\nprint(sys.argv)\nsys.stdout.write('x')\nsys.exit(0)"),
        ("getattr literal", "import json\nprint(json.loads(getattr(x, 'name')))"),
        ("csv to stdout", "import csv, sys\nw = csv.writer(sys.stdout)\nw.writerow([1])"),
        ("logging config without file", "import logging\nlogging.basicConfig(level=1)"),
        ("async def", "async def f():\n    await g()"),
        ("plain escapes", "print('a\\n\\t\\\\')\nprint(r'\\x2e')"),
        ("base64 encode", "import base64\nprint(base64.b64encode(b'x'))"),
        ("gzip.open text read", "import gzip, sys\nprint(gzip.open(sys.argv[1], 'rt').read())"),
        ("bytes decode", "print(b'abc'.decode('utf-8'))"),
    ];

    const REJECT: &[(&str, &str)] = &[
        // parsing and size
        ("syntax error", "def f(:\n    pass"),
        ("python 2 print", "print 'x'"),
        ("python 2 exec", "exec 'x'"),
        ("unclosed paren", "print((1, 2)"),
        ("nul byte", "print(1)\0"),
        // imports
        ("subprocess", "import subprocess\nsubprocess.run(['ls'])"),
        ("subprocess from", "from subprocess import run\nrun(['ls'])"),
        ("shutil", "import shutil\nshutil.rmtree('x')"),
        ("shutil as", "import shutil as s\nprint(1)"),
        ("socket", "import socket"),
        ("ctypes", "import ctypes"),
        ("multiprocessing", "import multiprocessing"),
        ("threading", "import threading"),
        ("asyncio", "import asyncio"),
        ("importlib", "import importlib\nimportlib.import_module('os')"),
        ("pickle", "import pickle"),
        ("marshal", "import marshal"),
        ("tempfile", "import tempfile"),
        ("builtins", "import builtins"),
        ("relative import", "from . import x"),
        ("wildcard import", "from os import *"),
        ("unknown submodule", "import xml.dom.minidom"),
        ("html submodule", "import html.parser"),
        ("package name import", "from urllib import something"),
        ("os name import", "from os import remove"),
        ("os environ import", "from os import environ"),
        ("sys modules import", "from sys import modules"),
        ("import in function", "def f():\n    import subprocess"),
        ("alias of callee", "from urllib.request import urlopen as u\nu('http://x', b'd')"),
        ("alias of deny", "from os import path as eval"),
        // builtins
        ("eval", "eval('1')"),
        ("exec", "exec('x=1')"),
        ("compile", "compile('1', 'f', 'eval')"),
        ("__import__", "__import__('os')"),
        ("dunder builtins", "print(__builtins__)"),
        ("dunder class", "print((1).__class__)"),
        ("dunder globals", "print(f.__globals__)"),
        ("getattr dynamic", "import json\ngetattr(json, name)"),
        ("getattr dangerous", "getattr(x, 'system')"),
        ("getattr as value", "f = getattr\nf(x, 'a')"),
        ("setattr dynamic", "setattr(x, n, 1)"),
        ("setattr data", "setattr(req, 'data', b'x')"),
        ("delattr dynamic", "delattr(x, n)"),
        ("globals", "print(globals())"),
        ("locals", "print(locals())"),
        ("vars empty", "print(vars())"),
        ("vars module", "import os\nvars(os)"),
        ("input", "input()"),
        ("input bare", "x = input"),
        ("breakpoint", "breakpoint()"),
        ("methodcaller", "import operator\noperator.methodcaller('x')"),
        // open
        ("open w", "open('a', 'w').write('x')"),
        ("open a", "open('a', 'a')"),
        ("open x", "open('a', 'x')"),
        ("open plus", "open('a', 'r+')"),
        ("open wb kw", "open('a', mode='wb')"),
        ("open dynamic mode", "open('a', m)"),
        ("open dynamic mode kw", "open('a', mode=m)"),
        ("open opener", "open('a', opener=o)"),
        ("open as value", "f = open\nf('a', 'w')"),
        ("Path.open w", "from pathlib import Path\nPath('a').open('w')"),
        ("Path.open dynamic", "from pathlib import Path\nPath('a').open(m)"),
        ("Path.open mode kw", "from pathlib import Path\nPath('a').open(mode='a')"),
        ("gzip write", "import gzip\ngzip.open('a.gz', 'wt')"),
        ("io.open w", "import io\nio.open('a', 'w')"),
        ("FileIO", "import io\nio.FileIO('a', 'w')"),
        ("argparse FileType", "import argparse\nargparse.FileType('w')"),
        ("open splat", "open(*a)"),
        ("print to file", "import sys\nf = sys.stdout\nprint('x', file=f)"),
        ("print to open file", "print('x', file=out)"),
        ("print kwargs", "print('x', **k)"),
        // mutators
        ("os.remove", "import os\nos.remove('a')"),
        ("os.unlink", "import os\nos.unlink('a')"),
        ("os.rmdir", "import os\nos.rmdir('a')"),
        ("os.rename", "import os\nos.rename('a', 'b')"),
        ("os.replace", "import os\nos.replace('a', 'b')"),
        ("os.replace alias", "import os as o\no.replace('a', 'b')"),
        ("os.makedirs", "import os\nos.makedirs('a')"),
        ("os.mkdir", "import os\nos.mkdir('a')"),
        ("os.chmod", "import os\nos.chmod('a', 0o700)"),
        ("os.chown", "import os\nos.chown('a', 0, 0)"),
        ("os.symlink", "import os\nos.symlink('a', 'b')"),
        ("os.link", "import os\nos.link('a', 'b')"),
        ("os.truncate", "import os\nos.truncate('a', 0)"),
        ("os.open", "import os\nos.open('a', os.O_WRONLY)"),
        ("os.system", "import os\nos.system('ls')"),
        ("os.popen", "import os\nos.popen('ls')"),
        ("os.execv", "import os\nos.execv('/bin/ls', ['ls'])"),
        ("os.spawnl", "import os\nos.spawnl(0, '/bin/ls')"),
        ("os.kill", "import os\nos.kill(1, 9)"),
        ("os passed around", "import os\nf = os\nf.system('ls')"),
        ("os as argument", "import os\nprint(vars(os))"),
        ("os.path.expandvars", "import os\nprint(os.path.expandvars('$HOME'))"),
        ("Path.unlink", "from pathlib import Path\nPath('a').unlink()"),
        ("Path.rmdir", "from pathlib import Path\nPath('a').rmdir()"),
        ("Path.rename", "from pathlib import Path\nPath('a').rename('b')"),
        ("Path.replace one arg", "from pathlib import Path\nPath('a').replace('b')"),
        ("Path.mkdir", "from pathlib import Path\nPath('a').mkdir()"),
        ("Path.touch", "from pathlib import Path\nPath('a').touch()"),
        ("Path.chmod", "from pathlib import Path\nPath('a').chmod(0)"),
        ("Path.symlink_to", "from pathlib import Path\nPath('a').symlink_to('b')"),
        ("Path.write_text", "from pathlib import Path\nPath('a').write_text('x')"),
        ("Path.write_bytes", "from pathlib import Path\nPath('a').write_bytes(b'x')"),
        ("file.write", "f.write('x')"),
        ("file.writelines", "f.writelines(['x'])"),
        ("stdout aliased write", "import sys\nout = sys.stdout\nout.write('x')"),
        ("modules through sys", "import sys\nsys.modules['shutil']"),
        ("sys.settrace", "import sys\nsys.settrace(None)"),
        ("json.dump to file", "import json\njson.dump({}, open('a.json', 'w'))"),
        ("writes json file", "import json\nwith open('out.json', 'w') as f:\n    json.dump({}, f)"),
        ("del subscript", "d = {}\ndel d['a']"),
        ("del attribute", "del a.b"),
        ("del tuple of subscripts", "del a[0], b"),
        ("logging file", "import logging\nlogging.basicConfig(filename='a.log')"),
        ("logging FileHandler", "import logging\nlogging.FileHandler('a.log')"),
        // environment and credentials
        ("os.environ", "import os\nprint(os.environ['HOME'])"),
        ("os.environ get", "import os\nprint(os.environ.get('HOME'))"),
        ("os.getenv", "import os\nprint(os.getenv('HOME'))"),
        ("os.environb", "import os\nprint(os.environb)"),
        ("os alias environ", "import os as o\nprint(o.environ)"),
        ("getpass", "import getpass\ngetpass.getpass()"),
        ("keyring", "import keyring"),
        ("proc environ", "print(open('/proc/self/environ').read())"),
        // secret files
        ("ssh key", "print(open('/Users/a/.ssh/id_rsa').read())"),
        ("ssh key via Path", "from pathlib import Path\nprint((Path.home() / '.ssh' / 'k').read_text())"),
        ("id_ed25519", "print(open('id_ed25519').read())"),
        ("aws", "print(open('/root/.aws/credentials').read())"),
        ("dotenv", "print(open('.env').read())"),
        ("dotenv local", "print(open('.env.local').read())"),
        ("netrc", "print(open('/root/.netrc').read())"),
        ("npmrc", "print(open('.npmrc').read())"),
        ("kube config", "print(open('/root/.kube/config').read())"),
        ("gnupg", "print(open('/root/.gnupg/x').read())"),
        ("docker config", "print(open('/root/.docker/config.json').read())"),
        ("shadow", "print(open('/etc/shadow').read())"),
        ("pem", "print(open('server.pem').read())"),
        ("key", "print(open('server.key').read())"),
        ("secret in fstring", "h = 1\nprint(open(f'{h}/.ssh/id_rsa').read())"),
        ("secret split across literals", "print(open('/root/.s' 'sh/id_rsa').read())"),
        // network writes
        ("urlopen data", "import urllib.request\nurllib.request.urlopen('http://x', b'd')"),
        ("urlopen data kw", "import urllib.request\nurllib.request.urlopen('http://x', data=b'd')"),
        ("Request data", "import urllib.request\nurllib.request.Request('http://x', b'd')"),
        ("Request data kw", "import urllib.request\nurllib.request.Request('http://x', data=b'd')"),
        ("Request method POST", "import urllib.request\nurllib.request.Request('http://x', method='POST')"),
        ("Request method DELETE", "import urllib.request\nurllib.request.Request('http://x', method='DELETE')"),
        ("Request method variable", "import urllib.request\nurllib.request.Request('http://x', method=m)"),
        ("Request kwargs", "import urllib.request\nurllib.request.Request('http://x', **k)"),
        ("Request subclass", "import urllib.request\nclass R(urllib.request.Request):\n    pass"),
        ("Request assigned data", "import urllib.request\nr = urllib.request.Request('http://x')\nr.data = b'x'"),
        ("Request assigned method", "import urllib.request\nr = urllib.request.Request('http://x')\nr.method = 'PUT'"),
        ("Request get_method", "import urllib.request\nr = urllib.request.Request('http://x')\nr.get_method = lambda: 'DELETE'"),
        ("Request tuple store", "r.data, x = 1, 2"),
        ("Request as value", "import urllib.request\nf = urllib.request.Request\nf('http://x', b'd')"),
        ("urlopen as value", "from urllib.request import urlopen\nprint(list(map(urlopen, ['http://x'])))"),
        ("urlretrieve", "import urllib.request\nurllib.request.urlretrieve('http://x', 'a')"),
        ("opener open", "import urllib.request\nurllib.request.build_opener().open(req)"),
        ("opener open data", "import urllib.request\nurllib.request.build_opener().open('http://x', b'd')"),
        ("requests post", "import requests\nrequests.post('http://x')"),
        ("requests put", "import requests\nrequests.put('http://x')"),
        ("requests patch", "import requests\nrequests.patch('http://x')"),
        ("requests delete", "import requests\nrequests.delete('http://x')"),
        ("requests request POST", "import requests\nrequests.request('POST', 'http://x')"),
        ("requests request variable", "import requests\nrequests.request(m, 'http://x')"),
        ("session post", "import requests\ns = requests.Session()\ns.post('http://x')"),
        ("httpx post", "import httpx\nhttpx.post('http://x')"),
        ("httpx stream post", "import httpx\nhttpx.stream('POST', 'http://x')"),
        ("httpx client send", "import httpx\nhttpx.Client().send(r)"),
        // sqlite
        ("sqlite file", "import sqlite3\nsqlite3.connect('a.db')"),
        ("sqlite rw uri", "import sqlite3\nsqlite3.connect('file:a.db?mode=rw', uri=True)"),
        ("sqlite ro without uri", "import sqlite3\nsqlite3.connect('file:a.db?mode=ro')"),
        ("sqlite dynamic", "import sqlite3\nsqlite3.connect(p, uri=True)"),
        ("sqlite from import", "from sqlite3 import connect\nconnect('a.db')"),
        ("sqlite attach", "import sqlite3\nc = sqlite3.connect('file:a.db?mode=ro', uri=True)\nc.execute(\"ATTACH 'b.db' AS b\")"),
        ("sqlite vacuum into", "import sqlite3\nc = sqlite3.connect(':memory:')\nc.execute(\"vacuum into 'x.db'\")"),
        ("sqlite extension", "import sqlite3\nsqlite3.connect(':memory:').enable_load_extension(True)"),
        // yaml code execution
        ("yaml load", "import yaml\nyaml.load(s, Loader=yaml.Loader)"),
        ("yaml unsafe_load", "import yaml\nyaml.unsafe_load(s)"),
        ("yaml from import load", "from yaml import load"),
        // hidden inside other constructs
        ("hidden in fstring", "import os\nprint(f'{os.system(1)}')"),
        ("hidden in lambda", "import os\nf = lambda: os.system('ls')"),
        ("hidden in decorator", "import os\n@os.remove\ndef f(): pass"),
        ("hidden in default", "import os\ndef f(a=os.remove('x')): pass"),
        ("hidden in class body", "import os\nclass A:\n    os.remove('x')"),
        ("hidden in comprehension", "import os\n[os.remove(p) for p in 'ab']"),
        // modules reached through attributes of allowed modules
        ("escape os via urllib", "import urllib.request\nurllib.request.os.remove('x')"),
        ("escape os via glob", "import glob\nglob.os.replace('a', 'b')"),
        ("escape os via os.path", "import os.path as p\np.os.remove('x')"),
        ("escape sys via logging", "import logging\nlogging.sys.modules"),
        ("escape http via urllib", "import urllib.request\nurllib.request.http.client.HTTPSConnection('x').putrequest('POST', '/')"),
        ("escape by from import", "from glob import os"),
        ("opener data kw", "import urllib.request\nurllib.request.build_opener().open('http://x', data=b'd')"),
        ("logging fileConfig", "import logging\nlogging.config.fileConfig('a.ini')"),
        // ways to hide a name from the rules
        ("full-width eval", "\u{ff45}\u{ff56}\u{ff41}\u{ff4c}('1')"),
        ("non-ascii attribute", "x.\u{ff52}emove('a')"),
        ("secret behind hex escape", "print(open('\\x2essh/k').read())"),
        ("secret behind unicode escape", "print(open('\\u002essh/k').read())"),
        ("secret behind octal escape", "print(open('\\056ssh/k').read())"),
        ("vars", "import argparse\na = argparse.ArgumentParser().parse_args()\nvars(a)['x'] = 1"),
        ("sqlite two modes", "import sqlite3\nsqlite3.connect('file:a.db?mode=rw&mode=ro', uri=True)"),
        ("sys.setrecursionlimit", "import sys\nsys.setrecursionlimit(10)"),
        // decoding an embedded blob hides a payload from a static check
        ("base64 decode and print", "import base64\nb64 = 'aGVsbG8gd29ybGQ='\nprint(base64.b64decode(b64).decode('utf-8'))"),
        ("base64 alias decode", "import base64 as b\nprint(b.urlsafe_b64decode('aA=='))"),
        ("base64 from import", "from base64 import b64decode\nprint(b64decode('aA=='))"),
        ("base64 stream decode", "import base64, sys\nbase64.decode(sys.stdin.buffer, sys.stdout.buffer)"),
        ("base64 b85", "import base64\nprint(base64.b85decode('x'))"),
        ("zlib decompress", "import zlib\nprint(zlib.decompress(b'x'))"),
        ("zlib decompressobj", "import zlib\nprint(zlib.decompressobj().decompress(b'x'))"),
        ("gzip decompress", "import gzip\nprint(gzip.decompress(b'x'))"),
        ("bytes.fromhex", "print(bytes.fromhex('00ff'))"),
        ("binascii unhexlify", "binascii.unhexlify('00')"),
    ];

    #[test]
    fn accepts_read_only_scripts() {
        for (name, source) in ACCEPT {
            assert!(
                read_only(source),
                "should be proven read-only: {name}\n{source}"
            );
        }
    }

    #[test]
    fn rejects_everything_else() {
        for (name, source) in REJECT {
            assert!(!read_only(source), "should NOT be proven: {name}\n{source}");
        }
    }

    #[test]
    fn rejects_oversized_input() {
        assert!(read_only("x = 1\n"));
        assert!(!read_only(&"x = 1\n".repeat(60_000)));
    }

    #[test]
    fn deep_nesting_neither_overflows_nor_hangs() {
        // 100 levels still parse and prove; the deeper ones must not.
        assert!(read_only(&format!(
            "x = {}1{}",
            "(".repeat(100),
            ")".repeat(100)
        )));
        for depth in [1_000, 20_000] {
            assert!(!read_only(&format!(
                "x = {}1{}",
                "(".repeat(depth),
                ")".repeat(depth)
            )));
            assert!(!read_only(&format!(
                "x = {}1{}",
                "[".repeat(depth),
                "]".repeat(depth)
            )));
            assert!(!read_only(&format!("x = {}", "a.".repeat(depth) + "b")));
            assert!(!read_only(&format!("x = {}", "-".repeat(depth) + "1")));
        }
        // Statement nesting.
        let mut nested = String::new();
        for i in 0..150 {
            nested.push_str(&format!("{}if x:\n", " ".repeat(i)));
        }
        nested.push_str(&format!("{}pass\n", " ".repeat(150)));
        assert!(!read_only(&nested));
        // Ordinary nesting stays provable.
        assert!(read_only("x = {'a': [{'b': (1, [2, {'c': 3}])}]}"));
    }

    #[test]
    fn odd_text_is_not_proven_and_never_panics() {
        for source in [
            "\u{feff}print(1)\u{ffff}",
            "print('\u{202e}')\n\u{0}",
            "\u{1b}[31mprint(1)",
            "x = '\u{d7ff}\u{e000}'\r\n\r\nprint(x)\r\n",
            "print(1)\n\\",
            "'''unterminated",
            "\t\tprint(1)",
            "def f(\n",
            "@",
            "lambda",
        ] {
            let _ = read_only(source);
        }
        assert!(!read_only("print(1)\0"));
        assert!(!read_only("\u{1b}[31mprint(1)"));
    }
}
