import re
from datetime import datetime

# 定义日志文件路径和输出文件路径
log_file_path = r"D:\Desktop\xx\xx\xxxxx.txt"
output_file_path = r'D:\Desktop\xx\xx\output.txt'
summary_file_path = r'D:\Desktop\xx\xx\汇总统计.txt'

# 创建一个字典来存储每个 pktid 的所有时间戳
pktid_times = {}

# 读取日志文件，并使用 GB2312 编码，同时处理可能的编码错误
with open(log_file_path, 'r', encoding='gb2312', errors='replace') as file:
    for line in file:
        # 使用正则表达式匹配日志行中的信息
        match = re.search(
            r'(\d{8} \d{2}:\d{2}:\d{2}\.\d{6}) \[WritePacket\]KSvrComm (AfterGet|Put|ReplyNull)\[pktid\((\d+)\)\], func: ?(\d+),.*',
            line)
        if match:
            timestamp_str, operation, pktid_str, func_str = match.groups()
            # 解析时间戳
            timestamp = datetime.strptime(timestamp_str, '%Y%m%d %H:%M:%S.%f')
            pktid = int(pktid_str)
            func = int(func_str)

            # 如果这个 pktid 还没有被记录过，则初始化一个新的列表
            if pktid not in pktid_times:
                pktid_times[pktid] = {'func': func, 'AfterGet': [], 'Put': []}

            # 将当前的时间戳和操作类型添加到对应的 pktid 列表中
            if operation == 'AfterGet':
                pktid_times[pktid]['AfterGet'].append(timestamp)
            elif operation in ['Put', 'ReplyNull']:
                pktid_times[pktid]['Put'].append(timestamp)

# 创建一个字典来存储每种功能的统计信息
func_stats = {}

# 遍历所有的 pktid 和它们的时间戳列表
for pktid, entries in pktid_times.items():
    afterget_timestamps = entries['AfterGet']
    put_timestamps = entries['Put']
    func = entries['func']

    if func not in func_stats:
        func_stats[func] = {
            'durations': [],
            'request_count': 0,
            'response_count': 0
        }

    # 增加请求计数
    func_stats[func]['request_count'] += len(afterget_timestamps)
    # 增加响应计数
    func_stats[func]['response_count'] += len(put_timestamps)

    if put_timestamps:
        # 找到最后一个 Put 时间戳
        last_put_time = max(put_timestamps)

        # 计算每个 AfterGet 到最后一个 Put 之间的时间差
        for afterget_time in afterget_timestamps:
            time_diff = (last_put_time - afterget_time).total_seconds()
            func_stats[func]['durations'].append(time_diff)

# 汇总统计信息
with open(summary_file_path, 'w', encoding='gb2312') as summary_file:
    for func, stats in func_stats.items():
        durations = stats['durations']
        request_count = stats['request_count']
        response_count = stats['response_count']

        if durations:
            max_duration = max(durations)
            min_duration = min(durations)
            avg_duration = sum(durations) / len(durations)
        else:
            max_duration = min_duration = avg_duration = 0

        summary_file.write(f"功能: {func}, 最大耗时: {max_duration:.6f}s, 最小耗时: {min_duration:.6f}s, 平均耗时: {avg_duration:.6f}s, 请求量: {request_count}, 应答量: {response_count}\n")

print(f"Results have been saved to {output_file_path}")
print(f"Summary statistics have been saved to {summary_file_path}")
