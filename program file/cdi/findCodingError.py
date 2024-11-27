# -*- coding: utf-8 -*-
import configparser
import os
import re

def read_config():
    config = configparser.ConfigParser()
    config.read('./config/config.ini')
    return config.get('Directories','search_dirs').split(';')

# 输出结果的文件
output_file = r'D:\combined_results.txt'

# 正则表达式1：用于找到 sErrMsg = "..." 形式的语句
pattern1 = re.compile(r'sErrMsg\s*=\s*"(.*?)"')
# 正则表达式2：用于找到 sNote.Format( 开头的行
pattern2 = re.compile(r'sNote\.Format\s*\(\s*')

def find_format_statements(content):
    results = []
    start_match = pattern2.search(content)
    while start_match:
        start_index = start_match.start()
        balance = 1
        end_index = -1
        for i, char in enumerate(content[start_index + len(start_match.group(0)):],
                                 start=start_index + len(start_match.group(0))):
            if char == '(':
                balance += 1
            elif char == ')':
                balance -= 1
            if balance == 0:
                end_index = i + 1
                break
        if end_index!= -1:
            statement = content[start_index:end_index]
            results.append(statement)
            start_match = pattern2.search(content, end_index)
        else:
            break
    return results

def search_in_file(file_path):
    unique_lines = set()
    try:
        with open(file_path, 'r', encoding='gb2312', errors='replace') as file:
            content = file.read()
            for line in content.splitlines():
                match1 = pattern1.search(line)
                if match1 and match1.group(1).strip():
                    line_to_write = f"{file_path} | {line.strip()}"
                    if line_to_write not in unique_lines:
                        unique_lines.add(line_to_write)
            matches2 = find_format_statements(content)
            for match in matches2:
                formatted_match = ' '.join(match.split())
                line_to_write = f"{file_path} | {formatted_match}"
                if line_to_write not in unique_lines:
                    unique_lines.add(line_to_write)
        with open(output_file, 'a', encoding='gb2312') as out:
            for unique_line in unique_lines:
                out.write(f"{unique_line}\n")
    except UnicodeDecodeError:
        print(f"无法解码文件 {file_path}，已跳过。")
    except Exception as e:
        print(f"处理文件 {file_path} 时发生错误: {e}")

def recursive_search(directories):
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.cpp'):
                    full_path = os.path.join(root, file)
                    search_in_file(full_path)

if __name__ == "__main__":
    open(output_file, 'w').close()
    search_dirs = read_config()
    recursive_search(search_dirs)
    print(f"搜索完成，结果已保存至 {output_file}")