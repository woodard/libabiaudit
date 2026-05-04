# List of test scripts to run
TESTS = \
    test_simple.sh \
    test_dlopen.sh \
    test_harmless.sh \
    test_e_flag.sh \
    test_mismatch.sh \
    test_reverse_mismatch.sh

# The -e flag test is a designated known failure
XFAIL_TESTS = test_e_flag.sh

# Ensure these scripts are included in 'make dist'
EXTRA_DIST = $(TESTS)

# Clean up all the dynamically generated test artifacts
clean-local:
	rm -f *.cpp *.so *_test *.dwo libabiaudit.so
