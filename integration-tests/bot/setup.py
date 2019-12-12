from setuptools import setup

setup(
    name='crypto-chain-bot',
    version='1.0',
    description='Prepare testnet environment for crypto-com chain.',
    author='yihuagn',
    author_email='huang@crypto.com',
    install_requires=[
        'PyNaCl==1.3.0',
        'python-decouple==3.3',
        'supervisor==4.1.0',
        'toml==0.10.0',
        'fire==0.2.1',
        'mnemonic==0.19',
        'jsonpatch==1.24',
        'jsonrpcclient[requests]',
    ],
    scripts=[
        'chainbot.py',
        'chainrpc.py',
    ]
)
