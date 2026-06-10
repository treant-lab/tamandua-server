#!/bin/bash

# E2E Test Runner for Tamandua EDR
# Usage: ./run_e2e_tests.sh [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
BROWSER_MODE="${WALLABY_BROWSER:-headless}"
TEST_FILE=""
VERBOSE=false
SETUP_DB=false
TRACE=false

# Print usage
usage() {
    cat << EOF
E2E Test Runner for Tamandua EDR

Usage: ./run_e2e_tests.sh [OPTIONS]

Options:
    -a, --all           Run all E2E tests
    -f, --file FILE     Run specific test file (e.g., auth_test.exs)
    -v, --visible       Run with visible browser (for debugging)
    -t, --trace         Run with trace output
    -s, --setup         Setup test database before running
    -h, --help          Show this help message

Examples:
    # Run all E2E tests
    ./run_e2e_tests.sh -a

    # Run specific test file with visible browser
    ./run_e2e_tests.sh -f auth_test.exs -v

    # Run all tests with database setup
    ./run_e2e_tests.sh -a -s

    # Run with trace output
    ./run_e2e_tests.sh -f dashboard_test.exs -t

Test Suites:
    auth_test.exs             - Authentication and authorization
    dashboard_test.exs        - Dashboard widgets and real-time updates
    alerts_test.exs           - Alert management and triage
    agents_test.exs           - Agent monitoring and control
    threat_hunting_test.exs   - Query builder and hunting workflows
    settings_test.exs         - Configuration management
    compliance_test.exs       - Compliance frameworks and reporting

EOF
}

# Print colored message
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if ChromeDriver is installed
check_chromedriver() {
    if ! command -v chromedriver &> /dev/null; then
        print_message "$RED" "ERROR: ChromeDriver not found!"
        print_message "$YELLOW" "Please install ChromeDriver:"
        print_message "$BLUE" "  macOS:   brew install chromedriver"
        print_message "$BLUE" "  Ubuntu:  sudo apt-get install chromium-chromedriver"
        print_message "$BLUE" "  Windows: Download from https://chromedriver.chromium.org/"
        exit 1
    fi
}

# Setup test database
setup_database() {
    print_message "$BLUE" "Setting up test database..."
    MIX_ENV=test mix ecto.drop 2>/dev/null || true
    MIX_ENV=test mix ecto.create
    MIX_ENV=test mix ecto.migrate
    print_message "$GREEN" "Database setup complete!"
}

# Create screenshots directory
setup_screenshots() {
    mkdir -p tmp/screenshots
    print_message "$BLUE" "Screenshots will be saved to: tmp/screenshots/"
}

# Run tests
run_tests() {
    local test_path=$1
    local env_vars=""
    local mix_args=""

    # Set browser mode
    if [ "$BROWSER_MODE" = "visible" ]; then
        env_vars="WALLABY_BROWSER=visible"
        print_message "$YELLOW" "Running with VISIBLE browser..."
    else
        print_message "$BLUE" "Running with HEADLESS browser..."
    fi

    # Set trace if requested
    if [ "$TRACE" = true ]; then
        mix_args="$mix_args --trace"
        print_message "$BLUE" "Running with TRACE output..."
    fi

    # Run the tests
    print_message "$GREEN" "Running tests: $test_path"
    print_message "$BLUE" "----------------------------------------"

    if [ -n "$env_vars" ]; then
        env $env_vars MIX_ENV=test mix test $test_path $mix_args
    else
        MIX_ENV=test mix test $test_path $mix_args
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--all)
            TEST_FILE="test/e2e/"
            shift
            ;;
        -f|--file)
            TEST_FILE="test/e2e/$2"
            shift 2
            ;;
        -v|--visible)
            BROWSER_MODE="visible"
            shift
            ;;
        -t|--trace)
            TRACE=true
            shift
            ;;
        -s|--setup)
            SETUP_DB=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            print_message "$RED" "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_message "$GREEN" "========================================"
    print_message "$GREEN" "  Tamandua EDR - E2E Test Runner"
    print_message "$GREEN" "========================================"
    echo

    # Check prerequisites
    check_chromedriver

    # Setup database if requested
    if [ "$SETUP_DB" = true ]; then
        setup_database
        echo
    fi

    # Setup screenshots directory
    setup_screenshots
    echo

    # Check if test file/directory is specified
    if [ -z "$TEST_FILE" ]; then
        print_message "$RED" "ERROR: No test file specified!"
        echo
        usage
        exit 1
    fi

    # Check if test file exists
    if [ ! -e "$TEST_FILE" ]; then
        print_message "$RED" "ERROR: Test file not found: $TEST_FILE"
        exit 1
    fi

    # Run the tests
    run_tests "$TEST_FILE"

    echo
    print_message "$GREEN" "========================================"
    print_message "$GREEN" "  Test run complete!"
    print_message "$GREEN" "========================================"

    # Show screenshot location if any were taken
    if [ -n "$(ls -A tmp/screenshots 2>/dev/null)" ]; then
        echo
        print_message "$YELLOW" "Screenshots saved to: tmp/screenshots/"
    fi
}

# Run main function
main "$@"
