# TCC
Implementação de um módulo de Kernel Linux: Sistema anti-ransomware com abordagem de detecção de cifragem em tempo real.

Ubuntu 22.04

Kernel 5.15.0

# Compilar

make clean

make all

# Inserir módulo

sudo insmod tcc_kernel_module.ko

# Remover módulo

sudo rmmod tcc_kernel_module

# Testes
python3 legitimate.py
python3 malicious.py
