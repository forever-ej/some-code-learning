# -*- coding: gb2312 -*-
import re
from datetime import datetime, time
import configparser

# 读取配置文件
def read_config(config_path: str) -> tuple:
    config = configparser.ConfigParser()
    try:
        config.read(config_path)
        log_file = config.get('Paths', 'log_file')
        output_file = config.get('Paths', 'output_file')
        summary_file = config.get('Paths', 'summary_file')
        start_time_str = config.get('TimeRange', 'start_time', fallback=None)
        end_time_str = config.get('TimeRange', 'end_time', fallback=None)
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"配置文件错误: {e}")
        raise

    return log_file, output_file, summary_file, start_time_str, end_time_str

def parse_time(time_str: str) -> time:
    return time.fromisoformat(time_str) if time_str else None

# 根据日志文件进行相关格式化筛选处理
def process_log_line(line: str, pktid_times: dict, start_time: time, end_time: time):
    match = re.search(
        r'(\d{8} \d{2}:\d{2}:\d{2}\.\d{6}) \[WritePacket\]KSvrComm (AfterGet|Put|ReplyNull)\[pktid\((\d+)\)\], func: ?(\d+),.*',
        line)
    if not match:
        return

    timestamp_str, operation, pktid_str, func_str = match.groups()
    timestamp = datetime.strptime(timestamp_str, '%Y%m%d %H:%M:%S.%f')
    pktid = int(pktid_str)
    func = func_str

    if operation == 'AfterGet':
        current_time = timestamp.time()
        if start_time and end_time and not (start_time <= current_time <= end_time):
            return  # 如果不在指定时间段内，跳过此记录

        # 只有在指定时间段内的 AfterGet 才会被记录
        if pktid not in pktid_times:
            pktid_times[pktid] = {'func': func, 'AfterGet': [], 'Put': []}

        pktid_times[pktid]['AfterGet'].append(timestamp)

    # 对于 Put 或 ReplyNull，只记录那些已经在 pktid_times 中的 pktid
    elif operation in ['Put', 'ReplyNull'] and pktid in pktid_times:
        pktid_times[pktid]['Put'].append(timestamp)

# 计算时间差，保存在列表中
def calculate_time_diffs(pktid_times: dict) -> list:
    time_diffs = []

    for pktid, entries in pktid_times.items():
        afterget_timestamps = entries['AfterGet']
        put_timestamps = entries['Put']
        func = entries['func']

        if put_timestamps:
            last_put_time = max(put_timestamps)
            for afterget_time in afterget_timestamps:
                duration = (last_put_time - afterget_time).total_seconds()
                time_diffs.append({
                    'pktid': pktid,
                    'afterget_time': afterget_time,
                    'last_put_time': last_put_time,
                    'duration': duration,
                    'status': '成功',
                    'func': func
                })
        else:
            for afterget_time in afterget_timestamps:
                time_diffs.append({
                    'pktid': pktid,
                    'afterget_time': afterget_time,
                    'last_put_time': None,
                    'duration': None,
                    'status': '统计失败',
                    'func': func
                })

    return time_diffs

# 将逐笔分析结果写入输出文件
def write_output(output_file: str, time_diffs_sorted: list):
    with open(output_file, 'w', encoding='gb2312') as cus:
        for diff in time_diffs_sorted:
            if diff['status'] == '成功':
                cus.write(
                    f"func: {diff['func']}, pktid: {diff['pktid']}, AfterGet: {diff['afterget_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}, "
                    f"Last Put: {diff['last_put_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}, Duration: {diff['duration']} seconds, 状态: {diff['status']}\n")
            else:
                cus.write(
                    f"func: {diff['func']}, pktid: {diff['pktid']}, AfterGet: {diff['afterget_time'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}, "
                    f"Last Put: 无, Duration: 无, 状态: {diff['status']}\n")

# 计算功能统计信息，并保存在字典中
def calculate_func_stats(pktid_times: dict) -> dict:
    func_stats = {}

    for entries in pktid_times.values():
        afterget_timestamps = entries['AfterGet']
        put_timestamps = entries['Put']
        func = entries['func']

        if func not in func_stats:
            func_stats[func] = {
                'durations': [],
                'request_count': 0,
                'response_count': 0
            }

        func_stats[func]['request_count'] += len(afterget_timestamps)
        func_stats[func]['response_count'] += len(put_timestamps)

        if put_timestamps:
            last_put_time = max(put_timestamps)
            func_stats[func]['durations'].extend(
                (last_put_time - t).total_seconds() for t in afterget_timestamps
            )

    return func_stats

# 将功能统计信息写入汇总文件
def write_summary(summary_file: str, func_stats: dict):
    with open(summary_file, 'w', encoding='gb2312') as f:
        for func, stats in func_stats.items():
            durations = stats['durations']
            request_count = stats['request_count']
            response_count = stats['response_count']
            max_duration = max(durations, default=0)
            min_duration = min(durations, default=0)
            avg_duration = sum(durations) / len(durations) if durations else 0
            f.write(f"功能: {func}, 最大耗时: {max_duration:.6f}s, 最小耗时: {min_duration:.6f}s, 平均耗时: {avg_duration:.6f}s, 请求量: {request_count}, 应答量: {response_count}\n")

# 读取配置文件
config_path = 'LogAssay.ini'
try:
    log_file, output_file, summary_file, start_time_str, end_time_str = read_config(config_path)
    start_time = parse_time(start_time_str)
    end_time = parse_time(end_time_str)
except Exception as e:
    print(f"无法读取配置文件: {e}")
    exit(1)

# 创建一个字典来存储每个 pktid 的所有时间戳
pktid_times = {}

# 读取日志文件，并使用检测到的编码
with open(log_file, 'r', encoding='gb2312', errors='replace') as file:
    for line in file:
        process_log_line(line, pktid_times, start_time, end_time)

# 计算时间差
time_diffs = calculate_time_diffs(pktid_times)

# 按照状态是否为“成功”进行排序，如果是“成功”，则按时间差从大到小排序
time_diffs_sorted = sorted(time_diffs, key=lambda x: (x['status'] == '统计失败', -(x['duration'] or 0)))

# 将结果写入输出文件
write_output(output_file, time_diffs_sorted)

# 统计每种功能的信息
func_stats = calculate_func_stats(pktid_times)

# 写入汇总结果
write_summary(summary_file, func_stats)

print(f"日志分析【逐笔请求】结果已保存至 {output_file}")
print(f"日志分析【汇总结果】已保存至 {summary_file}")
