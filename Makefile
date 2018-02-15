# Only for running tests. Nothing else to make.

## Running tests:
# $ make                              -- Runs all tests
# $ make t/create-deposit-data.test   -- Runs a single test. Note there is no actual file by this name
#
## Writing tests:
# Create a t/foo.run bash script; make sure it is chmod +x.
# Create a matching t/foo.golden file; `touch t/foo.golden` is sufficient to start
# Run the test using `make t/foo.test`; it will fail since it doesn't match golden
# Manually check t/foo.out to ensure desired output
# $ mv t/foo.{out,golden}
# Ensure test passes now
# Commit!

SHELL := /bin/bash

all-tests := $(addsuffix .test, $(basename $(wildcard t/*.run)))

.PHONY : test all %.test


# Each test needs a clean bitcoind server running
.NOTPARALLEL:

# Simulate actual conditions on Quarantined Laptop...bitcoind will
# normally not be running yet and ~/.bitcoin will not exist
define cleanup_bitcoind =
@mkdir -p bitcoin-test-data
@bitcoin-cli -testnet -datadir=bitcoin-test-data stop >/dev/null 2>&1 || exit 0
@if pgrep bitcoind >/dev/null; then sleep 1; fi
@if pgrep bitcoind >/dev/null; then echo Error: unable to stop bitcoind; exit 1; fi
@rm -rf bitcoin-test-data
endef

test : $(all-tests)
	$(cleanup_bitcoind)
	@echo "Success, all tests passed."

OUTPUT = $(addsuffix .out, $(basename $<))

%.test : %.run %.golden glacierscript.py
	$(cleanup_bitcoind)
	@mkdir bitcoin-test-data
	$< 2>&1 > $(OUTPUT)
	@diff -q $(word 2, $?) $(OUTPUT) || \
	  (echo "Test $@ failed" && exit 1)
	@rm $(OUTPUT)
