#!/bin/bash

# Run tests with suppressed Qt warnings while preserving exit code.
# PIPESTATUS[0] propagates the test binary's exit so filtering never masks a failure.

export QT_LOGGING_RULES="qt.*=false"
export QT_MESSAGE_PATTERN="[%{type}] %{message}"

./OpenCryptUITest "$@" 2>&1 | grep -v "^QDEBUG : TestOpenCryptUI::initTestCase() \[debug\] qt\." | grep -v "^QDEBUG : TestOpenCryptUI::initTestCase() \[debug\] QFont::"
exit ${PIPESTATUS[0]}