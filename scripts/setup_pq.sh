# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
#
# setup for liboqs, if one wants to run it on its own machine.
sudo apt update
sudo apt install libssl-dev
sudo apt install cmake
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
# shellcheck disable=SC2164
cd liboqs-python
pip install .
# shellcheck disable=SC2103
cd ..
# sanity check, if an error occurs, the script will try to install itself,
# which resolves the problem.
python liboqs-python/examples/kem.py
