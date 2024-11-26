# -*- coding: gb2312 -*-
import logging
import os
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import chardet
import re
import configparser

# 配置日志，将日志级别设置为INFO，这样就不会输出DEBUG级别的调试信息了
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 读取配置文件
config = configparser.ConfigParser()
config.read('config.ini')

log_path = os.path.abspath(config.get('Paths', 'log_path'))
out_dir = os.path.abspath(config.get('Paths', 'out_dir'))
by_time = config.getboolean('Sorting', 'by_time')
interval = config.getint('TimeIntervals', 'interval')
auto_detect = config.getboolean('Encoding', 'auto_detect')
start_time = config.get('TimeIntervals', 'start_time')
end_time = config.get('TimeIntervals','end_time')

# 缓存编码
encoding_cache = {}

# 自动检测文件编码
def detect_encoding(file_path):
    if file_path in encoding_cache:
        return encoding_cache[file_path]
    with open(file_path, 'rb') as f:
        content = f.read(4096)  # 读取前4KB内容
        result = chardet.detect(content)
    encoding_cache[file_path] = result['encoding']
    return result['encoding']

# 解析单行日志
def parse_log_line(line):
    # 使用提供的正则表达式进行匹配
    match = re.search(
        r'(\d{8} \d{2}:\d{2}:\d{2}\.\d{6}) \[WritePacket\]KSvrComm (AfterGet|Put|ReplyNull)\[pktid\((\d+)\)\], func: ?(\d+),.*',
        line
    )
    if not match:
        return None

    # 提取匹配的组
    timestamp, action, pktid, func = match.groups()

    # 提取Info部分
    info_start = match.end() + 1  # 跳过空格或其他分隔符
    info = line[info_start:].strip()

    return {'timestamp': timestamp, 'pktid': pktid, 'func': func, 'action': action, 'info': info}

# 解析日志并计算所需信息
def parse_logs(log_path, encoding):
    logging.info(f"Parsing logs from: {log_path}")
    requests = {}
    with open(log_path, 'r', encoding=encoding, errors='replace') as file:
        for line in file:
            log_entry = parse_log_line(line)
            if not log_entry:
                continue

            pktid = log_entry['pktid']
            action = log_entry['action']
             # recv_time = datetime.strptime(log_entry['timestamp'], '%Y%m%d %H:%M:%S.%f').strftime('%H:%M:%S') # 新增时间戳格式化

            if action == 'AfterGet':
                # 初始化请求条目
                if pktid not in requests:
                    requests[pktid] = {
                        'func': log_entry['func'],
                        'recv_time': log_entry['timestamp'], # 修改为recv_time，原先为log_entry['timestamp']
                        'first_reply': None,
                        'last_reply': None,
                        'replies': [],
                        'success': False,
                        'pktid': pktid  # 确保 pktid 被设置
                    }
            elif action in ('Put', 'ReplyNull'):
                if pktid in requests:
                    requests[pktid]['replies'].append((log_entry['timestamp'], action))
                    if not requests[pktid]['first_reply']:
                        requests[pktid]['first_reply'] = log_entry['timestamp']
                    requests[pktid]['last_reply'] = log_entry['timestamp']
                    requests[pktid]['success'] = True
                else:
                    continue
            else:
                continue

    # 计算耗时
    for req in requests.values():
        if 'pktid' not in req:
            logging.error(f"Request is missing pktid: {req}")
            continue

        if req['replies']:
            recv_time = datetime.strptime(req['recv_time'], '%Y%m%d %H:%M:%S.%f')
            last_reply_time = datetime.strptime(req['last_reply'], '%Y%m%d %H:%M:%S.%f')
            req['proc_time'] = (last_reply_time - recv_time).total_seconds()
            if req['first_reply']:
                first_reply_time = datetime.strptime(req['first_reply'], '%Y%m%d %H:%M:%S.%f')
                req['output_time'] = (last_reply_time - first_reply_time).total_seconds()
            else:
                req['output_time'] = 0
        else:
            req['proc_time'] = 0
            req['output_time'] = 0

    return requests

# 写入请求数据
def write_requests(requests, out_dir_path, by_time=False):
    # 确保目录存在
    os.makedirs(out_dir_path, exist_ok=True)

    for req in requests.values():
        # if start_time <= req['recv_time'] <= end_time: # 检查时间是否在指定范围内
            with open(os.path.join(out_dir_path, 'requests.txt'), 'w', encoding='gb2312') as f:
                for req in requests.values():
                    if 'pktid' not in req or 'func' not in req or 'recv_time' not in req:
                        continue
                    f.write(f"pktid: {req['pktid']}, func: {req['func']}, recv_time: {req['recv_time']}, ")
                    f.write(f"first_reply: {req.get('first_reply', 'N/A')}, last_reply: {req.get('last_reply', 'N/A')}, ")
                    f.write(f"proc_time: {req.get('proc_time', 0) * 1000:.3f}ms, ")
                    f.write(f"output_time: {req.get('output_time', 0) * 1000:.3f}ms, success: {req['success']}\n")
        # else:
            # return  # 跳过不在指定时间范围内的请求

# 将每个功能的数据分别写入各自的文件中
def write_requests_per_function(requests, out_dir_path, by_time=False):
    # 确保目录存在
    os.makedirs(out_dir_path, exist_ok=True)

    # 按功能写入文件
    for func in set(req['func'] for req in requests.values()):
        with open(os.path.join(out_dir_path, f'requests_func_{func}.txt'), 'w', encoding='gb2312') as f:
            for req in requests.values():
                if req['func'] == func:
                    f.write(f"pktid: {req['pktid']}, recv_time: {req['recv_time']}, ")
                    f.write(f"first_reply: {req.get('first_reply', 'N/A')}, last_reply: {req.get('last_reply', 'N/A')}, ")
                    f.write(f"proc_time: {req.get('proc_time', 0) * 1000:.3f}ms, ")
                    f.write(f"output_time: {req.get('output_time', 0) * 1000:.3f}ms, success: {req['success']}\n")

# 生成汇总分析结果
def generate_summary(requests, out_dir_path):
    logging.info("Generating summary")
    summary = defaultdict(lambda: {
        'max_proc_time': 0,
        'min_proc_time': float('inf'),
        'avg_proc_time': 0,
        'req_count': 0,
        'reply_count': 0,
        'total_proc_time': 0
    })

    func_counts = Counter(req['func'] for req in requests.values())
    for req in requests.values():
        func = req['func']
        summary[func]['reply_count'] += len(req['replies'])
        summary[func]['total_proc_time'] += req['proc_time']
        summary[func]['max_proc_time'] = max(summary[func]['max_proc_time'], req['proc_time'])
        summary[func]['min_proc_time'] = min(summary[func]['min_proc_time'], req['proc_time'])

    for func in func_counts:
        summary[func]['req_count'] = func_counts[func]
        if summary[func]['req_count'] > 0:
            summary[func]['avg_proc_time'] = summary[func]['total_proc_time'] / summary[func]['req_count']

    # 写入汇总文件
    summary_file = os.path.join(out_dir_path, 'summary.txt')
    with open(summary_file, 'w', encoding='utf-8') as f:
        for func, data in sorted(summary.items()):
            f.write(f"func: {func}, max_proc_time: {data['max_proc_time']:.3f}s, "
                    f"min_proc_time: {data['min_proc_time'] * 1000:.3f}ms, "
                    f"avg_proc_time: {data['avg_proc_time'] * 1000:.3f}ms, "
                    f"req_count: {data['req_count']}, reply_count: {data['reply_count']}\n")

# 生成每个时间段的统计数据
def generate_intervals(requests, out_dir_path, interval):
    logging.info("Generating intervals")
    intervals = defaultdict(lambda: {
        'req_count': 0,
        'reply_count': 0,
        'total_proc_time': 0
    })

    for req in requests.values():
        recv_time = datetime.strptime(req['recv_time'], '%Y%m%d %H:%M:%S.%f')
        interval_start = recv_time - timedelta(seconds=(recv_time.second % interval),
                                               microseconds=recv_time.microsecond)
        intervals[interval_start]['req_count'] += 1
        intervals[interval_start]['reply_count'] += len(req['replies'])
        intervals[interval_start]['total_proc_time'] += req['proc_time']

    # 写入时间间隔统计文件
    intervals_file = os.path.join(out_dir_path, 'intervals.txt')
    with open(intervals_file, 'w', encoding='utf-8') as f:
        for interval, data in sorted(intervals.items()):
            avg_proc_time = data['total_proc_time'] / data['req_count'] if data['req_count'] > 0 else 0
            f.write(f"interval: {interval.strftime('%Y%m%d %H:%M:%S')}, req_count: {data['req_count']}, "
                    f"reply_count: {data['reply_count']}, avg_proc_time: {avg_proc_time * 1000:.3f}ms\n")

# 主函数
def main():
    try:
        encoding = detect_encoding(log_path) if auto_detect else 'gb2312'
        requests = parse_logs(log_path, encoding)
        write_requests(requests, out_dir, by_time)
        write_requests_per_function(requests, out_dir, by_time)
        generate_summary(requests, out_dir)
        generate_intervals(requests, out_dir, interval)
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()
