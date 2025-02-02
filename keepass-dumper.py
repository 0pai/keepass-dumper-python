import re
import sys
import os
from collections import defaultdict

def is_valid_char(char):
	return bool(re.match(r'^[\x20-\xFF]+$', char))

def read_memory_dump(file_path, buffer_size=524288):
	candidates = defaultdict(set)
	current_str_len = 0
	debug_str = ""
	password_char = "●"
	
	with open(file_path, 'rb') as f:
		while chunk := f.read(buffer_size):
			i = 0
			while i < len(chunk) - 1:
				if chunk[i] == 0xCF and chunk[i + 1] == 0x25:
					current_str_len += 1
					i += 2
					debug_str += password_char
				else:
					if current_str_len == 0:
						i += 1
						continue
					
					current_str_len += 1
					
					try:
						char = chunk[i:i+2].decode('utf-16-le')
					except UnicodeDecodeError:
						i += 1
						continue
					
					if is_valid_char(char):
						candidates[current_str_len].add(char)
						debug_str += char
						print(f"Found: {debug_str}")
					
					current_str_len = 0
					debug_str = ""
					i += 1
	
	return candidates, password_char

def generate_pwd_list(candidates, pwd_list, unknown_char, pwd="", prev_key=0):
	for key in sorted(candidates.keys()):
		while key != prev_key + 1:
			pwd += unknown_char
			prev_key += 1
		
		prev_key = key
		
		if len(candidates[key]) == 1:
			pwd += next(iter(candidates[key]))
			continue
		
		for val in candidates[key]:
			generate_pwd_list(
				{k: v for k, v in candidates.items() if k > key},
				pwd_list,
				unknown_char,
				pwd + val,
				prev_key
			)
		return
	pwd_list.append(pwd)

def main():
	if len(sys.argv) < 2:
		print("Please specify a file path as an argument.")
		return
	
	file_path = sys.argv[1]
	if not os.path.exists(file_path):
		print("File not found.")
		return
	
	pwd_list_path = sys.argv[2] if len(sys.argv) >= 3 else ""
	candidates, password_char = read_memory_dump(file_path)
	
	print("\nPassword candidates (character positions):")
	print(f"Unknown characters are displayed as \"{password_char}\"")
	
	print(f"1.:	{password_char}")
	combined = password_char
	count = 2
	
	for key in sorted(candidates.keys()):
		while key > count:
			print(f"{count}.:	{password_char}")
			combined += password_char
			count += 1
		
		print(f"{key}.:	", end="")
		if len(candidates[key]) > 1:
			combined += "{"
		
		combined += ", ".join(candidates[key])
		
		if len(candidates[key]) > 1:
			combined += "}"
		
		print(", ".join(candidates[key]))
		count += 1
	
	print(f"Combined: {combined}")
	
	if pwd_list_path:
		pwd_list = []
		generate_pwd_list(candidates, pwd_list, password_char)
		with open(pwd_list_path, "w", encoding="utf-8") as f:
			f.write("\n".join(pwd_list))
		
		print(f"{len(pwd_list)} possible passwords saved in {pwd_list_path}. Unknown characters indicated as {password_char}")

if __name__ == "__main__":
	main()
