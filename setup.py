from setuptools import setup
import os, re

def read(*names, **kwargs):
    with open(os.path.join(os.path.dirname(__file__), *names), encoding='utf8') as fp:
        return fp.read()

def find_value(name):
    data_file = read('pproxy', '__doc__.py')
    data_match = re.search(r"^__%s__ += ['\"]([^'\"]*)['\"]" % name, data_file, re.M)
    if data_match:
        return data_match.group(1)
    raise RuntimeError(f"Unable to find '{name}' string.")

setup(
    name                = find_value('title'),
    version             = find_value('version'),
    description         = find_value('description'),
    long_description    = read('README.rst'),
    url                 = find_value('url'),
    author              = find_value('author'),
    author_email        = find_value('email'),
    license             = find_value('license'),
    python_requires     = '>=3.6',
    keywords            = find_value('keywords'),
    packages            = ['pproxy'],
    # 应该就是一些说明
    classifiers         = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    extras_require      = {
        'accelerated': [
            'pycryptodome >= 3.7.2',
        ],
        'sshtunnel': [
            'asyncssh >= 1.16.0',
        ],
    },
    install_requires    = [],
    # 就像注册了一个快捷命令一样，指定执行的方法
    entry_points        = {
        'console_scripts': [
            'pproxy = pproxy.server:main',
        ],
    },
)
