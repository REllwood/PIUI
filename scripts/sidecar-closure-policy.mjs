const DOCUMENTATION_DIRECTORY_SEGMENTS = new Set([
  'doc',
  'docs',
  'example',
  'examples',
  'test',
  'tests',
]);

const DOCUMENTATION_FILE_PREFIXES = [
  'readme',
  'changelog',
  'history',
  'contributing',
  'code_of_conduct',
  'security',
];
const DOCUMENTATION_EXTENSION = /\.(?:md|markdown|mdx|rst)$/i;
const LEGAL_FILE_PREFIX = /^(?:licen[cs]e|notice)(?:$|[._-])/i;
const OPSLEVEL_FILE = /^opslevel\.ya?ml$/i;

function isDocumentationSegment(value) {
  return DOCUMENTATION_DIRECTORY_SEGMENTS.has(value.toLowerCase());
}

function hasForbiddenDocumentationDirectory(segments) {
  if (segments.length === 0) return false;
  // Only a direct stage-root directory is documentation by position.
  if (isDocumentationSegment(segments[0])) return true;

  // At every (including nested) node_modules boundary, identify the exact
  // package root and reject only its immediate documentation child.
  for (let index = 0; index < segments.length; index += 1) {
    if (segments[index].toLowerCase() !== 'node_modules') continue;
    const packageStart = index + 1;
    if (packageStart >= segments.length) continue;
    const scoped = segments[packageStart].startsWith('@');
    const documentationIndex = scoped ? packageStart + 2 : packageStart + 1;
    if (
      documentationIndex < segments.length
      && isDocumentationSegment(segments[documentationIndex])
    ) return true;
  }
  return false;
}

export function isForbiddenDocumentationDirectoryPath(path) {
  return hasForbiddenDocumentationDirectory(path.split('/').filter(Boolean));
}

export function isForbiddenDocumentationFile(name) {
  if (LEGAL_FILE_PREFIX.test(name)) return false;
  const lowerName = name.toLowerCase();
  const extensionlessDocumentationName = !lowerName.includes('.')
    && DOCUMENTATION_FILE_PREFIXES.some((prefix) => (
      lowerName === prefix
      || lowerName.startsWith(`${prefix}-`)
      || lowerName.startsWith(`${prefix}_`)
      || lowerName.startsWith(`${prefix} `)
    ));
  return extensionlessDocumentationName
    || DOCUMENTATION_EXTENSION.test(name)
    || OPSLEVEL_FILE.test(name);
}

export function isForbiddenDocumentationPath(path) {
  const segments = path.split('/').filter(Boolean);
  if (segments.length === 0) return false;
  return hasForbiddenDocumentationDirectory(segments.slice(0, -1))
    || isForbiddenDocumentationFile(segments[segments.length - 1]);
}
