from setuptools import setup, find_packages

setup(
    name='xor-tool',
    version='1.0.0',
    description='Simple CLI tool for file encryption using XOR and AES (with pattern support)',
    author='Dx4Grey',
    author_email='dxablack@gmail.com',  # Ganti email kalau mau
    url='https://github.com/DX4GREY/xor-tools',  # Ganti URL repo kamu
    packages=find_packages(),
    py_modules=['xor_tool'],  # Nama file utama lo, misal xor_tool.py
    entry_points={
        'console_scripts': [
            'xor-tool=xor_tool:main',
        ],
    },
    install_requires=[
        'pycryptodome>=3.18.0',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography',
    ],
    python_requires='>=3.7',
)