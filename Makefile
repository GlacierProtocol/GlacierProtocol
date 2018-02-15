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

# Force parallel even when user was too lazy to type -j4
MAKEFLAGS += --jobs=4

# I need a unique port number for each bitcoind launched. Start with
# one higher than standard testnet port 18332, in case user already
# has a testnet daemon running.
compteur = 18333
# From https://stackoverflow.com/a/34156169/202201
# For target, given by the first parameter, set current *compteur* value.
# After issuing the rule, issue new value for being assigned to *compteur*.
define set_compteur
$(1): compteur = $(compteur) # Variable-assignment rule
compteur = $(shell echo $$(($(compteur)+1))) # Update variable's value
endef

$(foreach t,$(all-tests),$(eval $(call set_compteur, $(t))))


# Simulate actual conditions on Quarantined Laptop...bitcoind will
# normally not be running yet and ~/.bitcoin will not exist
define cleanup_bitcoind =
@mkdir -p $(RUNDIR)/bitcoin-test-data
@bitcoin-cli -testnet -rpcport=$(compteur) -datadir=$(RUNDIR)/bitcoin-test-data stop >/dev/null 2>&1 || exit 0
@if pgrep --full "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep --full "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep --full "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep --full "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then sleep 1; fi
@if pgrep --full "^bitcoind -testnet -rpcport=$(compteur)" >/dev/null; then echo Error: unable to stop bitcoind on port $(compteur); exit 1; fi
@rm -rf $(RUNDIR)/bitcoin-test-data
endef

test : $(all-tests)
	@rmdir testrun
	@echo "Success, all tests passed."

OUTPUT = $(addsuffix .out, $(basename $<))
RUNDIR = testrun/$(notdir $@)


%.test : %.run %.golden glacierscript.py
	$(cleanup_bitcoind)
	@mkdir -p $(RUNDIR)/bitcoin-test-data
	cd $(RUNDIR) && ../../$< $(compteur) 2>&1 > ../../$(OUTPUT)
	@diff -q $(word 2, $?) $(OUTPUT) || \
	  (echo "Test $@ failed" && exit 1)
	$(cleanup_bitcoind)
	@rm -rf $(RUNDIR)
	@rm $(OUTPUT)
