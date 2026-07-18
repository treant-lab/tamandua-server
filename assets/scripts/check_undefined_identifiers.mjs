import ts from 'typescript'
import process from 'node:process'

const configPath = ts.findConfigFile(process.cwd(), ts.sys.fileExists, 'tsconfig.json')
if (!configPath) {
  console.error('Unable to find tsconfig.json')
  process.exit(2)
}

const configFile = ts.readConfigFile(configPath, ts.sys.readFile)
if (configFile.error) {
  console.error(ts.formatDiagnostic(configFile.error, formatHost()))
  process.exit(2)
}

const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, process.cwd())
const program = ts.createProgram(parsed.fileNames, {
  ...parsed.options,
  noEmit: true,
})

// Vite transpiles TypeScript without type-checking. These diagnostics represent
// identifiers that would otherwise survive the build and crash in the browser.
const undefinedIdentifierCodes = new Set([2304, 2552])
const diagnostics = ts
  .getPreEmitDiagnostics(program)
  .filter(diagnostic => undefinedIdentifierCodes.has(diagnostic.code))

if (diagnostics.length > 0) {
  console.error(ts.formatDiagnosticsWithColorAndContext(diagnostics, formatHost()))
  process.exit(1)
}

console.log('Undefined identifier gate passed.')

function formatHost() {
  return {
    getCanonicalFileName: fileName => fileName,
    getCurrentDirectory: () => process.cwd(),
    getNewLine: () => ts.sys.newLine,
  }
}
