# The Problem

Storing user credentials in a plain `.txt` file or even in a database, without any encryption or protection is a major security flaw. If someone gains access, they can easily read all user credentials. This exposes users to identity theft, account breaches, and serious privacy risks.

# Concepts of Secure Data Storage

## What is Hashing?

Hashing is a process that takes an input ***(like a password)*** and turns it into a long, fixed-length string of characters. This string is called a hash.

Once something is hashed, you can’t reverse it to get the original input. That’s why it’s called a one-way function — it's like putting something through a shredder with no way to put the pieces back together.

Hashing is important for password storage because it means the system never has to save your actual password. Instead, it saves only the hash.

<p align="center">
  <img src="../assets/hash.png" alt="Descrição da imagem" width="100%"/>
</p>