from setuptools import setup, find_packages

setup(
    name='chiper-x',
    version='1.0.0',
    description='File encryption (with pattern support)',
    author='Dx4Grey',
    author_email='dxablack@gmail.com',  # Ganti email kalau mau
    url='https://github.com/DX4GREY/chiper-x',  # Ganti URL repo kamu
    packages=find_packages(),
    py_modules=['run'],  # Nama file utama lo, misal xor_tool.py
    entry_points={
        'console_scripts': [
            'chiper-x=run:main',
        ],
    },
    install_requires=[],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography',
    ],
    python_requires='>=3.7',
)