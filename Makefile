#
# Copyright 2014 Quantopian, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
all: requirements clean style test

clean:
	python etc/clean.py

style:
	flake8 qdb tests

test:
	nosetests tests/

requirements:
	pip install -r etc/requirements_dev.txt
	pip install -r etc/requirements.txt
	python -c 'import sys;exit(int(sys.version_info.major != 2))' && pip install -r etc/requirements_gevent.txt
