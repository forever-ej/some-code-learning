# -*- coding: utf-8 -*-
import logging
import os
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import chardet
import re
import configparser

# ��缃��ュ�锛�灏��ュ�绾у��璁剧疆涓�INFO锛�杩��峰氨涓�浼�杈���DEBUG绾у����璋�璇�淇℃��浜�
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 璇诲����缃���浠�
config = configparser.ConfigParser()
config.read('./config/config.ini')

log_path = os.path.abspath(config.get('Paths', 'log_path'))
out_dir = os.path.abspath(config.get('Paths', 'out_dir'))
by_time = config.getboolean('Sorting', 'by_time')
interval = config.getint('TimeIntervals', 'interval')
auto_detect = config.getboolean('Encoding', 'auto_detect')
start_time = config.get('TimeIntervals', 'start_time')
end_time = config.get('TimeIntervals','end_time')

# 缂�瀛�缂���
encoding_cache = {}

# ���ㄦ�娴���浠剁���
def detect_encoding(file_path):
    if file_path in encoding_cache:
        return encoding_cache[file_path]
    with open(file_path, 'rb') as f:
        content = f.read(4096)  # 璇诲����4KB��瀹�
        result = chardet.detect(content)
    encoding_cache[file_path] = result['encoding']
    return result['encoding']

# 瑙ｆ����琛��ュ�
def parse_log_line(line):
    # 浣跨�ㄦ��渚���姝ｅ��琛ㄨ揪寮�杩�琛��归��
    match = re.search(
        r'(\d{8} \d{2}:\d{2}:\d{2}\.\d{6}) \[WritePacket\]KSvrComm (AfterGet|Put|ReplyNull)\[pktid\((\d+)\)\], func: ?(\d+),.*',
        line
    )
    if not match:
        return None

    # �����归����缁�
    timestamp, action, pktid, func = match.groups()

    # ����Info�ㄥ��
    info_start = match.end() + 1  # 璺宠�绌烘�兼���朵�����绗�
    info = line[info_start:].strip()

    return {'timestamp': timestamp, 'pktid': pktid, 'func': func, 'action': action, 'info': info}

# 瑙ｆ���ュ�骞惰�＄������淇℃��
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
             # recv_time = datetime.strptime(log_entry['timestamp'], '%Y%m%d %H:%M:%S.%f').strftime('%H:%M:%S') # �板��堕�存�虫�煎���

            if action == 'AfterGet':
                # ��濮���璇锋��＄��
                if pktid not in requests:
                    requests[pktid] = {
                        'func': log_entry['func'],
                        'recv_time': log_entry['timestamp'], # 淇��逛负recv_time锛�����涓�log_entry['timestamp']
                        'first_reply': None,
                        'last_reply': None,
                        'replies': [],
                        'success': False,
                        'pktid': pktid  # 纭�淇� pktid 琚�璁剧疆
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

    # 璁＄������
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

# ���ヨ�锋��版��
def write_requests(requests, out_dir_path, by_time=False):
    # 纭�淇���褰�瀛���
    os.makedirs(out_dir_path, exist_ok=True)

    for req in requests.values():
        # if start_time <= req['recv_time'] <= end_time: # 妫��ユ�堕�存�����ㄦ��瀹����村��
            with open(os.path.join(out_dir_path, 'requests.txt'), 'w', encoding='gb2312') as f:
                for req in requests.values():
                    if 'pktid' not in req or 'func' not in req or 'recv_time' not in req:
                        continue
                    f.write(f"pktid: {req['pktid']}, func: {req['func']}, recv_time: {req['recv_time']}, ")
                    f.write(f"first_reply: {req.get('first_reply', 'N/A')}, last_reply: {req.get('last_reply', 'N/A')}, ")
                    f.write(f"proc_time: {req.get('proc_time', 0) * 1000:.3f}ms, ")
                    f.write(f"output_time: {req.get('output_time', 0) * 1000:.3f}ms, success: {req['success']}\n")
        # else:
            # return  # 璺宠�涓��ㄦ��瀹��堕�磋���村����璇锋�

# 灏�姣�涓����界���版���������ュ��������浠朵腑
def write_requests_per_function(requests, out_dir_path, by_time=False):
    # 纭�淇���褰�瀛���
    os.makedirs(out_dir_path, exist_ok=True)

    # �����藉���ユ��浠�
    for func in set(req['func'] for req in requests.values()):
        with open(os.path.join(out_dir_path, f'requests_func_{func}.txt'), 'w', encoding='gb2312') as f:
            for req in requests.values():
                if req['func'] == func:
                    f.write(f"pktid: {req['pktid']}, recv_time: {req['recv_time']}, ")
                    f.write(f"first_reply: {req.get('first_reply', 'N/A')}, last_reply: {req.get('last_reply', 'N/A')}, ")
                    f.write(f"proc_time: {req.get('proc_time', 0) * 1000:.3f}ms, ")
                    f.write(f"output_time: {req.get('output_time', 0) * 1000:.3f}ms, success: {req['success']}\n")

# ����姹��诲����缁���
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

    # ���ユ��绘��浠�
    summary_file = os.path.join(out_dir_path, 'summary.txt')
    with open(summary_file, 'w', encoding='utf-8') as f:
        for func, data in sorted(summary.items()):
            f.write(f"func: {func}, max_proc_time: {data['max_proc_time']:.3f}s, "
                    f"min_proc_time: {data['min_proc_time'] * 1000:.3f}ms, "
                    f"avg_proc_time: {data['avg_proc_time'] * 1000:.3f}ms, "
                    f"req_count: {data['req_count']}, reply_count: {data['reply_count']}\n")

# ����姣�涓��堕�存�电��缁�璁℃�版��
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

    # ���ユ�堕�撮�撮��缁�璁℃��浠�
    intervals_file = os.path.join(out_dir_path, 'intervals.txt')
    with open(intervals_file, 'w', encoding='utf-8') as f:
        for interval, data in sorted(intervals.items()):
            avg_proc_time = data['total_proc_time'] / data['req_count'] if data['req_count'] > 0 else 0
            f.write(f"interval: {interval.strftime('%Y%m%d %H:%M:%S')}, req_count: {data['req_count']}, "
                    f"reply_count: {data['reply_count']}, avg_proc_time: {avg_proc_time * 1000:.3f}ms\n")

# 涓诲�芥��
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
