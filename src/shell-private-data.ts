import { homedir } from "node:os";
import { posix } from "node:path";
import { classifyReadPath } from "./gate.ts";
import {
	isPrivateReadBasename,
	PRIVATE_CONFIG_GLOB_DIRECTORY_CANDIDATES,
	PRIVATE_GLOB_DIRECTORY_CANDIDATES,
	PRIVATE_GLOB_FILE_CANDIDATES,
} from "./path-rules.ts";

/**
 * Conservatively identifies shell actions that reference deterministic private
 * paths. Literal path candidates are classified by the same classifyReadPath()
 * rules used for read/grep/find/ls tools; glob handling consumes the same rule
 * catalog through representative candidates.
 */
export function commandReferencesPrivateData(
	command: string,
	cwd: string,
): boolean {
	const expanded = expandHomeReferences(command);
	if (referencesDynamicPiPath(expanded, cwd)) return true;

	const words = shellEvidenceWords(expanded);
	// A quoted string handed to a shell is a script, so it never gets the
	// prose relaxations: `bash -c "grep \s credentials"`, `bash <<< '...'`,
	// `printf '...' | sh`, `subprocess.run("""...""", shell=True)`.
	// Match the word the shell runs (`ba\sh` is `bash`), not the raw spelling.
	// A simple assignment counts: `S=sh; $S -c '...'` and `S=/bin/sh; ${S}`.
	const allowProse =
		!commandInvokesShell(words) &&
		!SCRIPT_RUNNER.test(expanded);
	const shellValues = words.map(({ text, value }) =>
		isWindowsStyle(text) ? text : value,
	);
	// Relative words after `cd dir` are also classified against `dir`:
	// `cd ~/.pi/agent; cat settings.json`.
	const cdDirectories = cdTargets(shellValues, cwd);
	// `find ~/.pi -name '*.json'` or `rg token ~/.config --include=*.yml`
	// reaches private files through an extension-only glob, so the
	// extension-only relaxation is off when a command names a directory that
	// holds private data.
	const relaxExtensions = !shellValues.some((value) =>
		shellWordVariants(value).some((variant) =>
			isPrivateDataAncestor(variant, cwd),
		),
	);
	for (const { text: token, value, quoted } of words) {
		// `--exclude=.env`, `--exclude-dir=.bundle`: a plain exclusion value never
		// reads. A token carrying whitespace, shell operators, `$`, or `..` (a
		// quoted script passed to eval/sh -c) is still scanned.
		if (
			/^--(?:exclude|ignore)(?:-dir)?=[^\s;&|<>()`$]*$/i.test(token) &&
			!token.includes("..")
		) {
			continue;
		}
		// Check the word the shell actually passes on. Unquoted escapes are
		// removed (`cat credentials\.json` opens `credentials.json`, `cat
		// cred"entials"\.json` too), except in Windows-style paths. Regex and
		// prose relaxations only apply to words with quoted parts.
		const shellValue = isWindowsStyle(token) ? token : value;
		for (const candidate of tokenValueCandidates(shellValue)) {
			if (!candidate) continue;
			if (
				pathPatternReferencesPrivateData(candidate, {
					allowProse: allowProse && quoted,
					allowRegex: quoted,
					relaxExtensions,
				})
			) {
				return true;
			}
			if (
				cdDirectories.length > 0 &&
				!/\s/.test(candidate) &&
				!candidate.startsWith("-") &&
				shellWordVariants(candidate).some((variant) =>
					cdDirectories.some(
						(directory) => classifyReadPath(variant, directory).private,
					),
				)
			) {
				return true;
			}
			// Classify what the shell would actually open: every brace expansion
			// and unescaped form (`~/.ss\h/id_rsa`, `skills/\.\./settings.json`).
			if (
				shellWordVariants(candidate).some(
					(variant) =>
						looksLikeLiteralPath(variant) &&
						classifyReadPath(variant, cwd).private,
				)
			) {
				return true;
			}
		}
	}
	return false;
}

function cdTargets(values: string[], cwd: string): string[] {
	const targets: string[] = [];
	let current = cwd;
	for (let index = 0; index < values.length - 1; index++) {
		if (values[index] !== "cd" && values[index] !== "pushd") continue;
		const target = values[index + 1] ?? "";
		if (!target || target === "-" || /[*?[\]{}$`]/.test(target)) continue;
		current = posix.resolve(current, target === "~" ? homedir() : target);
		targets.push(current);
	}
	return targets;
}

const PRIVATE_DATA_ANCESTORS = [
	"",
	homedir(),
	posix.join(homedir(), ".config"),
	posix.join(homedir(), ".local"),
	posix.join(homedir(), ".local", "share"),
];

/** A directory whose recursive contents include private data. */
function isPrivateDataAncestor(word: string, cwd: string): boolean {
	if (word !== "~" && word !== "/" && !looksLikeLiteralPath(word)) return false;
	if (/[*?[\]{}$]/.test(word) || isWindowsStyle(word)) return false;
	const resolved = posix
		.resolve(cwd, word === "~" ? homedir() : word)
		.replace(/\/+$/, "");
	if (PRIVATE_DATA_ANCESTORS.includes(resolved)) return true;
	const segments = resolved.toLowerCase().split("/");
	const last = segments.at(-1);
	return (
		last === ".pi" || (last === "agent" && segments.at(-2) === ".pi")
	);
}

export function looksLikePrivateGlob(glob: string): boolean {
	return pathPatternReferencesPrivateData(glob);
}

// Code that hands a string to a shell (Python, Node, Ruby, Perl, PHP).
const SCRIPT_RUNNER =
	/\b(?:os\.(?:system|popen|exec\w*|spawn\w*)|subprocess|shell\s*=\s*True|child_process|exec(?:Sync|File|FileSync)?\s*\(|spawn(?:Sync)?\s*\(|system\s*\(|popen\s*\(|Open3|IO\.popen|shell_exec|passthru|proc_open)|%x[({[]/;

const SHELL_INVOKER =
	/^(?:(?:ba|da|z|k|mk|c|tc|a|fi|y|lk)?sh|busybox|eval|source|watch|su|runuser|script|flock|parallel|tmux|\$\{?shell\}?)$/i;

function isShellInvoker(token: string): boolean {
	return SHELL_INVOKER.test(token.slice(token.lastIndexOf("/") + 1));
}

const SHELL_ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;
const SHELL_VARIABLE = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$|^\$([A-Za-z_][A-Za-z0-9_]*)$/;

function commandInvokesShell(words: ShellWord[]): boolean {
	if (words.some((word) => isShellInvoker(word.value))) return true;
	const shells = new Map<string, number>();
	for (let index = 0; index < words.length; index++) {
		const assigned = SHELL_ASSIGNMENT.exec(words[index]?.value ?? "");
		if (!assigned?.[1]) continue;
		if (isShellInvoker(assigned[2] ?? "")) shells.set(assigned[1], index);
		else shells.delete(assigned[1]);
	}
	return words.some((word, index) => {
		const match = SHELL_VARIABLE.exec(word.value);
		const name = match?.[1] ?? match?.[2];
		if (!name) return false;
		const assignedAt = shells.get(name);
		return assignedAt !== undefined && assignedAt < index;
	});
}

/**
 * The words the shell may actually see for one argument: the word itself,
 * each brace expansion, and (outside Windows-style paths and regex words)
 * the forms with `\x` escapes removed.
 */
function shellWordVariants(word: string): string[] {
	const variants = new Set([word, ...expandBracePatterns(word)]);
	const unescape =
		!isWindowsStyle(word) && (startsLikePath(word) || !looksLikeRegex(word));
	if (unescape) {
		for (const variant of [...variants]) {
			if (variant.includes("\\")) variants.add(variant.replace(/\\(.)/g, "$1"));
		}
	}
	return [...variants];
}

function expandHomeReferences(value: string): string {
	return value
		.replace(/\$\{HOME\}|\$HOME/gi, homedir())
		.replace(/(^|[\s'"=(])~(?=\/)/g, `$1${homedir()}`);
}

interface ShellWord {
	/** The word with quotes removed; unquoted `\x` kept as written. */
	text: string;
	/** The word as the shell passes it on: unquoted `\x` becomes `x`. */
	value: string;
	/** True when any part of the word was single- or double-quoted. */
	quoted: boolean;
}

function shellEvidenceWords(command: string): ShellWord[] {
	const tokens: ShellWord[] = [];
	let current = "";
	let value = "";
	let quoted = false;
	let quote: "'" | '"' | undefined;
	const flush = () => {
		if (current) tokens.push({ text: current, value, quoted });
		current = "";
		value = "";
		quoted = false;
	};

	const add = (text: string, shellValue = text) => {
		current += text;
		value += shellValue;
	};
	for (let index = 0; index < command.length; index++) {
		const character = command[index] ?? "";
		const next = command[index + 1] ?? "";
		if (quote === "'") {
			if (character === "'") quote = undefined;
			else add(character);
			continue;
		}
		if (quote === '"') {
			if (character === '"') {
				quote = undefined;
				continue;
			}
			if (character === "\\" && /["$`\\\n]/.test(next)) {
				index++;
				add(next);
				continue;
			}
			add(character);
			continue;
		}
		if (character === "'" || character === '"') {
			quote = character;
			quoted = true;
			continue;
		}
		if (/\s/.test(character) || /[;|&<>()]/.test(character)) {
			flush();
			continue;
		}
		if (character === "\\" && index + 1 < command.length) {
			index++;
			// `\<newline>` is a line continuation; `\x` is `x` to the shell.
			const shellValue = next === "\n" ? "" : next;
			if (/[\s'";|&<>()]/.test(next)) add(next === "\n" ? "" : next, shellValue);
			else add(`\\${next}`, shellValue);
			continue;
		}
		add(character);
	}
	flush();
	return tokens;
}

function tokenValueCandidates(token: string): string[] {
	const candidates = [token];
	const equals = token.lastIndexOf("=");
	if (equals >= 0 && equals < token.length - 1) {
		candidates.push(token.slice(equals + 1));
	}
	return candidates.map(cleanShellToken).filter(Boolean);
}

function cleanShellToken(token: string): string {
	return token.replace(/^[,:]+/, "").replace(/,+$/, "").trim();
}

function looksLikeLiteralPath(token: string): boolean {
	return (
		token.startsWith(".") ||
		token.startsWith("/") ||
		token.startsWith("~") ||
		token.startsWith("@") ||
		token.startsWith("file://") ||
		/^[a-z]:[\\/]/i.test(token) ||
		/^\\\\/.test(token) ||
		token.includes("/") ||
		token.includes("\\")
	);
}

interface PatternOptions {
	/** Quoted multi-line or regex text may be treated as prose. */
	allowProse?: boolean;
	/** Quoted words may be treated as regex. */
	allowRegex?: boolean;
	/** Extension-only globs such as `*.json` are a file type, not a name. */
	relaxExtensions?: boolean;
}

function pathPatternReferencesPrivateData(
	expression: string,
	{ allowProse = true, allowRegex = true, relaxExtensions = true }: PatternOptions = {},
): boolean {
	// Prose context: multi-line text (quoted multi-line strings) or a single
	// regex argument. There, words such as "credentials" are prose and
	// one-character glob fragments are noise. A regex-looking string that also
	// looks like a script (inner quotes, `;`, `&&`, `$(`, backticks) is never
	// prose, so `bash -c "grep '\s' credentials"` keeps its bare names.
	const scriptLike = /['"`;]|&&|\$\(/.test(expression);
	const prose =
		allowProse &&
		!scriptLike &&
		(/\n/.test(expression) || looksLikeRegex(expression));
	const words = [...new Set([expression, ...expression.split(/\s+/)])];
	return words.some((word) =>
		shellWordVariants(word).some((variant) =>
			wordReferencesPrivateData(variant, prose, allowRegex, relaxExtensions),
		),
	);
}

function wordReferencesPrivateData(
	word: string,
	prose: boolean,
	allowRegex: boolean,
	relaxExtensions: boolean,
): boolean {
	// Path-shaped words always get the full check: `~/.*/*\s` is a glob that
	// bash reads as `~/.*/*s`, not a regex.
	const pathShaped = startsLikePath(word);
	const regexLike = allowRegex && !pathShaped && looksLikeRegex(word);
	const proseWord = prose && !pathShaped;
	const source = regexLike ? stripRegexEscapes(word) : word;
	const tokens = [source, ...source.split(/[\s'"`;|&<>()]+/)]
		.map((token) => token.slice(token.lastIndexOf("=") + 1))
		.map(cleanShellToken)
		.filter(Boolean);
	return tokens.some((token) => {
		// Negated selectors (`rg -g '!**/.*'`) exclude paths; they never read them.
		if (
			token.startsWith("!") &&
			!/[\s;&|<>()`$]/.test(token) &&
			!token.includes("..")
		) {
			return false;
		}
		if (proseWord && !/[./\\*?[\]{}]/.test(token)) return false;
		const segments = token
			.replace(/\\/g, "/")
			.toLowerCase()
			.split("/")
			.filter(Boolean);
		for (let index = 0; index < segments.length; index++) {
			const pattern = segments[index] ?? "";
			if (isNoiseFragment(pattern, regexLike, proseWord)) continue;
			const extensionGlob = relaxExtensions
				? extensionOnlyGlobIsPrivate(pattern)
				: undefined;
			if (extensionGlob !== undefined) {
				if (extensionGlob) return true;
				continue;
			}
			if (
				[...PRIVATE_GLOB_DIRECTORY_CANDIDATES, ...PRIVATE_GLOB_FILE_CANDIDATES].some(
					(candidate) => shellGlobMatches(pattern, candidate),
				)
			) {
				return true;
			}
			if (
				index > 0 &&
				shellGlobMatches(segments[index - 1] ?? "", ".config") &&
				PRIVATE_CONFIG_GLOB_DIRECTORY_CANDIDATES.some((candidate) =>
					shellGlobMatches(pattern, candidate),
				)
			) {
				return true;
			}
		}
		return false;
	});
}

function startsLikePath(word: string): boolean {
	return /^(?:\/|~|\.\.?\/|[a-z]:[\\/]|\\\\)/i.test(word);
}

// Escapes that mark a regex. Shell/printf escapes (`\n`, `\t`, `\r`, `\1`)
// are deliberately absent so ordinary inline scripts are not treated as regex.
const REGEX_TRIGGER_ESCAPE = /\\[sSdDwWbB.|()[\]{}+*?^$\/<>]/;
// Escapes removed from a regex before glob matching.
const REGEX_STRIP_ESCAPE = /\\[sSdDwWbBntr.|()[\]{}+*?^$\/<>0-9]/g;

function looksLikeRegex(expression: string): boolean {
	return (
		REGEX_TRIGGER_ESCAPE.test(expression) ||
		/^\^/.test(expression) ||
		/\(\?/.test(expression) ||
		/\[\^/.test(expression) ||
		/\.\*[^/\s*]/.test(expression) ||
		/[^/\s.]\.\*/.test(expression) ||
		/^s([/|#,:@]).*\1.*\1[a-z0-9]*$/i.test(expression)
	);
}

function stripRegexEscapes(expression: string): string {
	return expression.replace(REGEX_STRIP_ESCAPE, " ");
}

function globLiteral(pattern: string): string {
	return pattern.replace(/\[[^\]]*\]/g, "").replace(/[*?{},]/g, "");
}

/**
 * Inside a regex word, `.*`/`.*?` are quantifiers. Inside prose (multi-line
 * text or a regex argument), one-character glob fragments such as `*a` or
 * `1***` are markdown/prose noise. Bare shell words such as `cat .*` or
 * `cat c*`, and single-line scripts such as `bash -c 'cat c*'`, stay private.
 */
function isNoiseFragment(
	pattern: string,
	regexLike: boolean,
	prose: boolean,
): boolean {
	if (!/[*?]/.test(pattern)) return false;
	if (/^\.[*?+]*$/.test(pattern)) return regexLike;
	return prose && globLiteral(pattern).length <= 1;
}

/**
 * Extension-only globs (`*.json`, `--include=*.yaml`, `*.{ts,json}`) describe
 * a file type, not a credential name. They are private only when the
 * extension itself is a private format such as `*.pem` or `*.env`.
 * Returns undefined when the pattern is not an extension-only glob.
 */
function extensionOnlyGlobIsPrivate(pattern: string): boolean | undefined {
	const expanded = expandBracePatterns(pattern);
	const extensions: string[] = [];
	for (const candidate of expanded) {
		const match = /^\*+\.([a-z0-9][a-z0-9_+-]*)\*?$/i.exec(candidate);
		if (!match?.[1]) return undefined;
		extensions.push(match[1]);
	}
	if (extensions.length === 0) return undefined;
	return extensions.some(
		(extension) =>
			isPrivateReadBasename(`file.${extension}`) || extension === "env",
	);
}

function shellGlobMatches(pattern: string, candidate: string): boolean {
	return expandBracePatterns(pattern).some((expanded) => {
		const literal = expanded.replace(/\[[^\]]*\]/g, "").replace(/[*?]/g, "");
		if (literal.length === 0) return false;
		let source = "^";
		for (let index = 0; index < expanded.length; index++) {
			const character = expanded[index];
			if (character === "*") {
				source += ".*";
			} else if (character === "?") {
				source += ".";
			} else if (character === "[") {
				const close = expanded.indexOf("]", index + 1);
				if (close < 0) {
					source += "\\[";
					continue;
				}
				let content = expanded.slice(index + 1, close);
				if (content.startsWith("!")) content = `^${content.slice(1)}`;
				source += `[${content}]`;
				index = close;
			} else {
				source += escapeRegExp(character);
			}
		}
		try {
			return new RegExp(`${source}$`, "i").test(candidate);
		} catch {
			return false;
		}
	});
}

function expandBracePatterns(pattern: string, depth = 0): string[] {
	if (depth >= 4) return [pattern];
	const match = /\{([^{}]+)\}/.exec(pattern);
	if (!match || match.index === undefined) return [pattern];
	const options = match[1].split(",");
	if (options.length === 0 || options.length > 16) return [pattern];
	const prefix = pattern.slice(0, match.index);
	const suffix = pattern.slice(match.index + match[0].length);
	return options
		.flatMap((option) =>
			expandBracePatterns(`${prefix}${option}${suffix}`, depth + 1),
		)
		.slice(0, 256);
}

// `.pi` as a real directory segment, not `.pi-agent/`, `tools.pi` or `self.pi_x`.
const PI_SEGMENT = /(?<![\w.-])\.pi(?![\w-])/i;

// Source and installed-package subtrees that docs/REFERENCE.md documents as
// not private solely because they live under `.pi/`.
const PI_PUBLIC_SUBTREE =
	/^\/(?:agent\/)?(?:skills|extensions|prompts|themes|agents|git|npm\/node_modules|context-mode\/insight-cache\/node_modules)\//i;

const SHELL_GLOB = /[*?[\]{}]/;

function isWindowsStyle(token: string): boolean {
	return /^[a-z]:[\\/]/i.test(token) || /^\\\\/.test(token);
}

/**
 * Normalizes one brace expansion the way the shell would see the path:
 * Windows-style tokens use `\` as a separator; elsewhere `\x` is a shell
 * escape for `x` (so `\.pi` is `.pi` and `'^\[tools\.pi\]'` is not a path).
 */
function normalizePiCandidate(token: string): string {
	return isWindowsStyle(token)
		? token.replace(/\\/g, "/")
		: token.replace(/\\(.)/g, "$1");
}

/**
 * True when a path under `.pi` may reach private Pi data. Called for every
 * brace expansion. Only the first `.pi` segment counts, and the public-subtree
 * exemption needs a literal prefix. A path that leaves the subtree through
 * `..` (or a glob that can match `..`, such as `.?`, `.[.]`, `[.][.]`) is not
 * exempt: literal paths are classified after resolving `..` and symlinks, and
 * globs stay private.
 */
function piCandidateIsPrivate(candidate: string, cwd: string): boolean {
	const path = normalizePiCandidate(candidate);
	const match = PI_SEGMENT.exec(path);
	if (!match || match.index === undefined) return false;
	if (path.includes("$")) return true;
	const prefix = path.slice(0, match.index);
	const rest = path.slice(match.index + match[0].length);
	const subtree = PI_PUBLIC_SUBTREE.exec(rest);
	if (subtree && !SHELL_GLOB.test(prefix)) {
		const tail = rest.slice(subtree[0].length).split("/");
		const leaves = tail.some(
			(segment) =>
				segment === ".." ||
				/[{}]/.test(segment) ||
				(SHELL_GLOB.test(segment) &&
					(segment.startsWith(".") || segment.startsWith("["))),
		);
		if (!leaves) return false;
	}
	if (!SHELL_GLOB.test(path)) return classifyReadPath(path, cwd).private;
	return true;
}

function referencesDynamicPiPath(command: string, cwd: string): boolean {
	const tokens = command.split(/[\s'"`;|&<>()]+/).filter(Boolean);
	if (
		tokens.some((token) =>
			expandBracePatterns(token).some((expanded) =>
				piCandidateIsPrivate(expanded, cwd),
			),
		)
	) {
		return true;
	}

	const assignments = command.matchAll(
		/(?:^|[;\s])([a-z_][a-z0-9_]*)\s*=\s*["']?([^;\s"']*\.pi[^;\s"']*)/gi,
	);
	for (const assignment of assignments) {
		const variable = assignment[1];
		if (!variable) continue;
		const value = assignment[2] ?? "";
		if (
			!expandBracePatterns(value).some((expanded) =>
				PI_SEGMENT.test(normalizePiCandidate(expanded)),
			)
		) {
			continue;
		}
		const remaining = command.slice(
			(assignment.index ?? 0) + assignment[0].length,
		);
		const variableReference = new RegExp(
			`\\$(?:${escapeRegExp(variable)}\\b|\\{${escapeRegExp(variable)}\\})`,
		);
		if (variableReference.test(remaining)) return true;
	}
	return false;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
