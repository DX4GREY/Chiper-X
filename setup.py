from setuptools import setup, find_packages

setup(
    name='chiper-x',
    version='2.1.2',
    description='File encryption (with pattern support)',
    author='Dx4Grey',
    author_email='dxablack@gmail.com',  # Ganti email kalau mau
    url='https://github.com/DX4GREY/chiper-x',  # Ganti URL repo kamu
    packages=find_packages(),
    py_modules=['chiper_x'],  # Nama file utama lo, misal xor_tool.py
    entry_points={
        'console_scripts': [
            'chiper-x=chiper_x:main',
        ],
    },
    install_requires=[
        # 'tkinter',  # Tkinter untuk GUI
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography',
    ],
    python_requires='>=3.7',
)