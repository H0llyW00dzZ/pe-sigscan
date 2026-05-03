# Copyright 2026 H0llyW00dzZ
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all header build test fmt clippy clean

# Print ASCII art banner.
ifeq ($(OS),Windows_NT)
header:
	@echo                         _                            
	@echo    _ __   ___        __^(_^) __ _ ___  ___ __ _ _ __   
	@echo   ^| '_ \ / _ \_____ / _^| ^|/ _` / __^|/ __/ _` ^| '_ \  
	@echo   ^| ^|_^) ^|  __/_____\__ \ ^| ^(_^| \__ \ ^(_^| ^(_^| ^| ^| ^| ^| 
	@echo   ^| .__/ \___^|     ^|___/_^|\__, ^|___/\___\__,_^|_^| ^|_^| 
	@echo   ^|_^|                     ^|___/                      
	@echo.
	@echo   pe-sigscan by H0llyW00dzZ ^(@github.com/H0llyW00dzZ^)
	@echo.
else
header:
	@printf '%s\n' '                        _                             '
	@printf '%s\n' '   _ __   ___        __(_) __ _ ___  ___ __ _ _ __    '
	@printf '%s\n' '  | '"'"'_ \ / _ \_____ / _| |/ _` / __|/ __/ _` | '"'"'_ \   '
	@printf '%s\n' '  | |_) |  __/_____\__ \ | (_| \__ \ (_| (_| | | | |  '
	@printf '%s\n' '  | .__/ \___|     |___/_|\__, |___/\___\__,_|_| |_|  '
	@printf '%s\n' '  |_|                     |___/                       '
	@printf '%s\n' ''
	@printf '%s\n' '  pe-sigscan by H0llyW00dzZ (@github.com/H0llyW00dzZ) '
	@printf '%s\n' ''
endif

# Default target.
all: header build test

# Build the crate (debug)
build: header
	@echo :: Building...
	cargo build
	@echo :: Done.

# Run tests
test: header
	@echo :: Running tests...
	cargo test
	@echo :: Done.

# Check formatting
fmt: header
	@echo :: Checking fmt...
	cargo fmt -- --check
	@echo :: Done.

# Run clippy
clippy: header
	@echo :: Running clippy...
	cargo clippy -- -D warnings
	@echo :: Done.

# Clean build artifacts
clean: header
	@echo :: Cleaning...
	cargo clean
	@echo :: Done.
