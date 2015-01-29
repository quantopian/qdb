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
import os
from textwrap import dedent
from six import iteritems, itervalues
from tempfile import mkdtemp, NamedTemporaryFile
from unittest import TestCase

from qdb.config import QdbConfig, default_config
from qdb.utils import Nothing, Maybe


class QdbConfigTester(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contents = dedent(
            """\
            # FOR TESTING PURPOSES
            config = QdbConfig(**{
                'host': Just('user-set'),
                'port': Just('user-set'),
                'auth_msg': Just('user-set'),
                'default_file': Just('user-set'),
                'default_namespace': Just('user-set'),
                'eval_fn': Just('user-set'),
                'exception_serializer': Just('user-set'),
                'skip_fn': Just('user-set'),
                'pause_signal': Just('user-set'),
                'redirect_output': Just('user-set'),
                'retry_attepts': Just('user-set'),
                'uuid': Just('user-set'),
                'cmd_manager': Just('user-set'),
                'green': Just('user-set'),
                'repr_fn': Just('user-set'),
                'log_file': Just('user-set'),
                'execution_timeout': Just('user-set'),
            })
            """
        )
        cls.old_home = os.environ['HOME']
        cls.home = mkdtemp()
        os.environ['HOME'] = cls.home
        cls.profile_path = os.path.join(cls.home, '.qdb')
        cls.profile = open(cls.profile_path, 'w+')
        cls.profile.write(cls.contents)
        cls.profile.flush()

        cls.expected = QdbConfig(
            **{k: 'user-set' for k in QdbConfig.DEFAULT_OPTIONS}
        )

    @classmethod
    def teardown(cls):
        cls.profile.close()
        os.remove(cls.profile_path)
        os.rmdir(cls.home)
        os.environ['HOME'] = cls.old_home

    def _test_file(self, files=None, use_local=False, use_profile=False):
        """
        Tests reading a local file.
        """
        config = QdbConfig.get_config(
            files=files, use_local=use_local, use_profile=use_profile,
        )

        self.assertEqual(self.expected._asdict(), config._asdict())

    def test_local(self):
        """
        Tests reading the local file.
        """
        cwd = os.getcwd()
        os.chdir(self.home)
        try:
            self._test_file(use_local=True)
        finally:
            os.chdir(cwd)

    def test_profile(self):
        """
        Tests reading the profile file.
        """
        self._test_file(use_profile=True)

    def test_extra(self):
        """
        Tests reading an extra config file.
        """
        with NamedTemporaryFile(dir=self.home) as t:
            t.write(self.contents)
            t.flush()

            self._test_file(files=(t.name,))

    def test_extra_arg(self):
        """
        Tests that passing an extra argument gets caught.
        """
        extra_arg = 'extra'
        while extra_arg in QdbConfig.DEFAULT_OPTIONS:
            # Assert athat extra_arg is NOT a valid option.
            extra_arg += '_'

        with self.assertRaisesRegexp(ValueError, extra_arg):
            QdbConfig.get_config({extra_arg: None})

    def test_config_default_trample(self):
        """
        Tests that the default values in QdbConfig.DEFAULT_OPTIONS
        will trample Nothings that make it to final.
        """
        config = QdbConfig.get_config(
            {k: Nothing for k in QdbConfig.DEFAULT_OPTIONS},
            use_local=False,
            use_profile=False,
        ).final

        self.assertEqual(default_config.final, config)

    def test_nothing_trample(self):
        """
        Tests that nothings get trampled at the merge step.
        """
        self.assertEqual(default_config, QdbConfig().merge(default_config))

    def test_masked_trample(self):
        """
        Tests that Just values will overwrite Nothings.
        """
        dict_ = QdbConfig()._asdict()
        for n, (k, v) in enumerate(iteritems(dict_)):
            if n % 2:
                dict_[k] = Maybe.unit('user-set')

        config = QdbConfig(**dict_)

        for n, v in enumerate(itervalues(QdbConfig().merge(config)._asdict())):
            if n % 2:
                self.assertEqual(v, Maybe.unit('user-set'))
            else:
                self.assertIs(v, Nothing)

    def test_defaults_to_nothings(self):
        """
        Assumptions are made that an empty config will have
        all Nothing's in it. This test asserts this behavior.
        """
        for v in QdbConfig():
            self.assertIs(v, Nothing)

    def test_just_trample(self):
        """
        Tests that Just values trample other Just values.
        """
        config = QdbConfig(
            **{k: Maybe.unit('user-set') for k in QdbConfig.DEFAULT_OPTIONS}
        )
        self.assertEqual(config, default_config.merge(config))

    def test_config_namespace(self):
        """
        Tests that the default namespace has all the names we expect it to.
        """
        with NamedTemporaryFile() as f:
            f.write('\n'.join(QdbConfig._config_namespace()) + '\nconfig = {}')
            f.flush()

            QdbConfig.read_from_file(f.name)

    def test_values_wrapped(self):
        """
        Tests that passing concrete kewords to the QdbConfig constructor
        will construct Maybes that wrap them as Just value.
        """
        for k, v in \
                iteritems(QdbConfig(**QdbConfig.DEFAULT_OPTIONS)._asdict()):

            default_v = QdbConfig.DEFAULT_OPTIONS[k]
            self.assertNotIsInstance(default_v, Maybe)
            self.assertEqual(v, Maybe.unit(default_v))
