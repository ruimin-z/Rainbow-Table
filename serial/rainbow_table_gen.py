import hashlib
import string

# Define the character set (for password generation)
chars = string.printable
chars_len = len(chars) # 100

def reduce(i):
    # Reduces an integer 'i' to a 6-character password
    pwd = ""
    while len(pwd) < 6: 
        pwd += chars[i % chars_len]
        i //= chars_len
    return pwd


# Generate a table of chains (start -> end)
table = []
for s in range(10):  # Generate 10 chains
    start = reduce(s)  # Initial plaintext
    p = start
    for _ in range(5):
        # Hash the current plaintext
        h = hashlib.md5(p.encode('ascii')).hexdigest()
        # Reduce the hash value to get the next plaintext
        tmp = p
        p = reduce(int(h, 16))
        table.append([(tmp, p, h)])  # Add to the table


# Print the table (start -> end pairs)
print(table)
