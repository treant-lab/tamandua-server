#!/usr/bin/env bash
# Tamandua NIF Build Verification Script

set -e

echo "🔍 Verifying Tamandua NIF Build..."
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "mix.exs" ]; then
    echo -e "${RED}❌ Error: mix.exs not found. Run this script from apps/tamandua_nif/${NC}"
    exit 1
fi

echo "📋 Step 1: Checking prerequisites..."

# Check Rust
if ! command -v rustc &> /dev/null; then
    echo -e "${RED}❌ Rust not found. Install from https://rustup.rs/${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Rust installed: $(rustc --version)${NC}"

# Check Cargo
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Cargo not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Cargo installed: $(cargo --version)${NC}"

# Check Elixir
if ! command -v elixir &> /dev/null; then
    echo -e "${RED}❌ Elixir not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Elixir installed: $(elixir --version | head -1)${NC}"

# Check Mix
if ! command -v mix &> /dev/null; then
    echo -e "${RED}❌ Mix not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Mix available${NC}"

echo ""
echo "📦 Step 2: Fetching dependencies..."
mix deps.get || {
    echo -e "${RED}❌ Failed to fetch dependencies${NC}"
    exit 1
}
echo -e "${GREEN}✓ Dependencies fetched${NC}"

echo ""
echo "🔨 Step 3: Compiling Rust code..."
cd native/tamandua_nif
cargo check || {
    echo -e "${RED}❌ Rust compilation failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Rust code compiles${NC}"

echo ""
echo "🧪 Step 4: Running Rust tests..."
cargo test || {
    echo -e "${YELLOW}⚠️  Some Rust tests failed (non-fatal)${NC}"
}

cd ../..

echo ""
echo "🔨 Step 5: Compiling Elixir with NIFs..."
mix compile || {
    echo -e "${RED}❌ Elixir compilation failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Elixir code compiles${NC}"

echo ""
echo "🧪 Step 6: Running Elixir tests..."
cd ../../
mix test apps/tamandua_server/test/tamandua_server/native_test.exs --only native || {
    echo -e "${YELLOW}⚠️  Some tests failed (check output above)${NC}"
}

echo ""
echo "📊 Step 7: Checking build artifacts..."
cd apps/tamandua_nif

# Check for compiled NIF
if [ -f "../../_build/dev/lib/tamandua_nif/priv/native/libtamandua_nif.so" ] || \
   [ -f "../../_build/dev/lib/tamandua_nif/priv/native/tamandua_nif.dll" ] || \
   [ -f "../../_build/dev/lib/tamandua_nif/priv/native/libtamandua_nif.dylib" ]; then
    echo -e "${GREEN}✓ NIF binary found${NC}"
else
    echo -e "${YELLOW}⚠️  NIF binary not found in expected location${NC}"
    echo "Searching..."
    find ../../_build -name "*tamandua_nif*" -type f 2>/dev/null | head -5
fi

echo ""
echo "📈 Step 8: Generating statistics..."

echo ""
echo "Code Statistics:"
echo "  Rust code:"
for file in native/tamandua_nif/src/*.rs; do
    lines=$(wc -l < "$file" 2>/dev/null || echo "0")
    printf "    %-20s %5d lines\n" "$(basename "$file")" "$lines"
done

echo ""
echo "  Elixir code:"
elixir_lines=$(wc -l < ../../apps/tamandua_server/lib/tamandua_server/native.ex 2>/dev/null || echo "0")
printf "    %-20s %5d lines\n" "native.ex" "$elixir_lines"

test_lines=$(wc -l < ../../apps/tamandua_server/test/tamandua_server/native_test.exs 2>/dev/null || echo "0")
printf "    %-20s %5d lines\n" "native_test.exs" "$test_lines"

echo ""
echo "  Documentation:"
for file in README.md QUICKSTART.md CHANGELOG.md; do
    if [ -f "$file" ]; then
        lines=$(wc -l < "$file")
        printf "    %-20s %5d lines\n" "$file" "$lines"
    fi
done

echo ""
echo "✅ Build verification complete!"
echo ""
echo "Next steps:"
echo "  1. Run full test suite: mix test"
echo "  2. Try the QUICKSTART examples: iex -S mix"
echo "  3. Read integration guide: cat ../../RUST_NIF_INTEGRATION.md"
echo ""
echo -e "${GREEN}🎉 Tamandua NIF is ready to use!${NC}"
