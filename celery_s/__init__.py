import re
import tempfile
import time
import datetime

import requests
import os

from celery import Celery
from celery.signals import task_success, task_prerun, task_failure
from mongoengine import disconnect, connect
from py2neo import Graph, Node, Relationship
from redis import StrictRedis
from mtools.transform import get_asm_from_bytes, get_bytes_from_file
from mtools.malware_classification.scripts.transform import pe2bmp
from mtools.malware_classification.predict import predict as predict_cls
from mtools.malware_sim.predict import predict as predict_sim

from .config import config
from .models.feature import Info, Static, Target, Behavior, Feature, Local


def make_app(config_name=None):
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'development')
    conf = config[config_name]
    app = Celery(__name__, broker=conf.CELERY_BROKER_URL, backend=conf.CELERY_BROKER_BACKEND)
    app.config_from_object(conf)
    setattr(app, 'config', conf)
    return app


app = make_app()


@task_prerun.connect
def task_prerun_handler(sender=None, headers=None, body=None, **kwargs):
    redis_client = StrictRedis(host=app.config.REDIS_HOST, port=6379, db=0, decode_responses=True)
    tl_lock = redis_client.setnx('lock:tl', 1)  # lock for task list
    try:
        if tl_lock:
            redis_client.hset('task_hash', sender.request.id, 'RUNNING')
    finally:
        redis_client.delete('lock:tl')


@task_success.connect
def task_success_handler(sender=None, result=None, **kwargs):
    redis_client = StrictRedis(host=app.config.REDIS_HOST, port=6379, db=0, decode_responses=True)
    tl_lock = redis_client.setnx('lock:tl', 1)  # lock for task list
    try:
        if tl_lock:
            redis_client.hset('task_hash', sender.request.id, 'SUCCESS')
    finally:
        redis_client.delete('lock:tl')


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, args=None, kwarg=None, traceback=None, einfo=None,
                         **kwargs):
    redis_client = StrictRedis(host=app.config.REDIS_HOST, port=6379, db=0, decode_responses=True)
    tl_lock = redis_client.setnx('lock:tl', 1)  # lock for task list
    try:
        if tl_lock:
            redis_client.hset('task_hash', sender.request.id, 'EXCEPTION')
    finally:
        redis_client.delete('lock:tl')


@app.task
def submit(f, id, apt_family):
    """
    :param f: bytes stream
    :param id: task id
    """
    try:
        connect(**app.config.MONGODB_SETTINGS)
        g = Graph(app.config.NEO4J_SETTINGS['url'],
                  auth=(app.config.NEO4J_SETTINGS['username'], app.config.NEO4J_SETTINGS['password']))

        res = Feature(task_id=id)
        if apt_family is not None:
            res.apt_family = apt_family
        with open(f, 'rb') as fp:
            res.upload.put(fp)

        upath = f
        af, afpath = tempfile.mkstemp(
            suffix='.asm')
        bf, bfpath = tempfile.mkstemp(suffix='.bytes')
        pf, pfpath = tempfile.mkstemp(suffix='.bmp')

        get_bytes_from_file(upath, bfpath)
        get_asm_from_bytes(bfpath, afpath)
        pe2bmp(upath, pfpath)

        res.local = Local()

        res.local.asm_file.put(open(af, 'rb'))
        res.local.bytes_file.put(open(bf, 'rb'))
        res.local.bmp_file.put(open(pf, 'rb'))

        res.local.malware_classification_resnet34 = predict_cls(
            pfpath)
        res.local.malware_sim_doc2vec = predict_sim(bfpath)

        # 将概率列表转化为概率字典
        t = {}
        prob_families = ['Ramnit', 'Lollipop', 'Kelihos_ver3', 'Vundo',
                         'Simda', 'Tracur', 'Kelihos_ver1', 'Obfuscator', 'Gatak']
        for k, v in zip(prob_families, res.local.malware_classification_resnet34):
            t[k] = v
        res.local.malware_classification_resnet34 = t

        # 上传任务到cuckoo
        file = {"file": (res.task_id, res.upload)}
        headers = {
            "Authorization": app.config.CUCKOO_TOKEN}
        r = requests.post(
            app.config.CUCKOO_URL +
            '/tasks/create/file',
            files=file,
            headers=headers)
        cuckoo_task_id = str(r.json()['task_id'])

        # 轮询获取报告
        done = False
        # import remote_pdb; remote_pdb.RemotePdb('127.0.0.1', 4444).set_trace()
        while not done:
            time.sleep(3)
            r = requests.get(
                app.config.CUCKOO_URL +
                '/tasks/view/' + str(cuckoo_task_id),
                headers=headers)
            if r.json()['task']['status'] == "reported":
                done = True

        cuckoo_report = requests.get(
            app.config.CUCKOO_URL +
            '/tasks/report/' + str(cuckoo_task_id),
            headers=headers).json()

        # 预处理报告
        sanity_correct({'report': cuckoo_report}, 'report')
        preprocessing(res, cuckoo_report)

        to_neo4j(g, res.to_json(), id)  # 保存结果到Neo4J    
        res.validate()
        res.save()  # 保存结果到mongodb
    finally:
        disconnect()


def sanity_correct(d, k):
    # 树形dfs遍历json报告
    if type(d[k]) == str:
        try:
            d[k] = d[k].encode(
                'utf-16', 'surrogatepass').decode('utf-16')
        except UnicodeDecodeError:
            d[k] = ascii(d[k])
            pass
    elif type(d[k]) == list:
        for i in range(len(d[k])):
            sanity_correct(d[k], i)
    elif type(d[k]) == dict:
        for i in d[k].keys():
            sanity_correct(d[k], i)
    else:
        return


def preprocessing(res, report):
    res.info = Info()
    res.info.package = report['info']['package']
    res.info.platform = report['info']['platform']

    res.target = Target()
    res.target.md5 = report['target']['file']['md5']
    res.target.urls = report['target']['file']['urls']
    res.target.name = report['target']['file']['name']

    res.static = Static()
    res.static.strings = report['strings']
    res.static.pe_imports = report['static']['pe_imports']
    res.static.pe_exports = report['static']['pe_exports']
    res.static.pe_resources = report['static']['pe_resources']
    res.static.pe_sections = report['static']['pe_sections']
    if 'pe_timestamp' in report['static']:
        res.static.pe_timestamp = datetime.datetime.strptime(
            report['static']['pe_timestamp'], '%Y-%m-%d %H:%M:%S')
    else:
        res.static.pe_timestamp = datetime.datetime.now()

    try:
        res.procmemory = report['procmemory']
    except KeyError:  # procmemory为可选字段
        pass

    try:
        res._buffer = report['buffer']
    except KeyError:  # buffer为可选字段
        pass

    try:
        res.behavior = Behavior()
        res.behavior.generic = report['behavior']['generic']
        if len(report['behavior']['processes']) > 1 and len(report['behavior']['processes'][1]['calls']) > 1000:
            # 只要前1000个call, 不然文件可能很大
            report['behavior']['processes'][1]['calls'] = report['behavior']['processes'][1]['calls'][:1000]
        res.behavior.processes = report['behavior']['processes']
        res.behavior.processtree = report['behavior']['processtree']
    except KeyError:  # behavior为可选字段
        pass

    for ops in ['file_opened', 'file_created', 'file_recreated', 'file_read', 'file_written', 'file_failed',
                'directory_created', 'dll_loaded', 'mutex', 'regkey_opened', 'regkey_read', 'regkey_written',
                'command_line', 'guid', 'extracted', 'dropped']:
        try:
            setattr(res.behavior, ops,
                    report['behavior']['summary'][ops])
        except KeyError:
            pass  # 忽略缺失字段
    try:
        res.signatures = report['signatures']
    except KeyError:  # signature为可选字段
        pass

    res.network = report['network']
    res.debug = report['debug']


def save_to_kg(res_json, filename):
    ip_local = ['192.168.56.101', '192.168.56.1', '255.255.255.255']  # 存放对分析无意义的本地ip和域名
    dllre = re.compile(r'([A-Za-z0-9]+(.dll|.DLL))')  # 获取DLL正则表达式
    mailre = re.compile(r"(\w+@\w+\.\w+)")  # 获取邮件的正则表达式
    ipre = re.compile(
        r'(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)')
    urlhttpre = re.compile(r"(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)")
    urlre = re.compile(r"((www|WWW)[.](?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)")

    # 定义存放提取字段的列表
    dll_list = []  # 存放dll
    ip_list = []  # 存放ip
    url_list = []  # 存放域名
    mail_list = []  # 存放的邮箱

    if dllre.findall(res_json):  # 导入dll
        for dll_re in dllre.findall(res_json):
            if '.' in dll_re[0]:
                dll_list.append(dll_re[0])

    if ipre.findall(res_json):  # and 'src' not in line and '192.168.56.101' not in line:  # 导入目的地址
        for ipa in ipre.findall(res_json):
            ww = ''
            ww = '.'.join(ipa)
            for ip_temp in ip_local:
                if ip_temp not in ww:
                    ip_list.append(ww)

    if urlre.findall(res_json):  # 导入http[s]url
        for urla in urlre.findall(res_json):
            for url_temp in ip_local:
                if url_temp not in urla[0]:
                    url_list.append(urla[0])

    if urlhttpre.findall(res_json):  # 导入url
        for urla in urlhttpre.findall(res_json):
            ww = ''
            for tup in urla:
                ww = ww + tup
                aa = ww.split('\\')
                ww = aa[0]
            url_list.append(ww)

    if mailre.findall(res_json):  # 导入邮箱
        for mail in mailre.findall(res_json):
            mail_list.append(mail)

    def string_duplicate_4(s):
        new_s = []
        for x in s:
            if x not in new_s:
                new_s.append(x)
        return new_s

    # 删除列表中重复的元素
    dll_list = string_duplicate_4(dll_list)
    ip_list = string_duplicate_4(ip_list)
    url_list = string_duplicate_4(url_list)
    mail_list = string_duplicate_4(mail_list)


def to_neo4j(g, res_json, filename):
    """
    g: the Graph object
    res_json: json string
    filename: malware name
    """

    def string_duplicate_4(s):
        new_s = []
        for x in s:
            if x not in new_s:
                new_s.append(x)
        return new_s

    """
    构建正则表达式以提取字段
    """
    """ from remote_pdb import RemotePdb
    RemotePdb("localhost", 4444).set_trace() """

    ip_local = ['192.168.56.101', '192.168.56.1', '255.255.255.255']  # 存放对分析无意义的本地ip和域名
    dllre = re.compile(r'([A-Za-z0-9]+(.dll|.DLL))')  # 获取DLL正则表达式
    mailre = re.compile(r"(\w+@\w+\.\w+)")  # 获取邮件的正则表达式
    ipre = re.compile(
        r'(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)')
    urlhttpre = re.compile(r"(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)")
    urlre = re.compile(r"((www|WWW)[.](?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)")

    # 定义存放提取字段的列表
    dll_list = []  # 存放dll
    ip_list = []  # 存放ip
    url_list = []  # 存放域名
    mail_list = []  # 存放的邮箱

    if dllre.findall(res_json):  # 导入dll
        for dll_re in dllre.findall(res_json):
            if '.' in dll_re[0]:
                dll_list.append(dll_re[0])

    if ipre.findall(res_json):  # and 'src' not in line and '192.168.56.101' not in line:  # 导入目的地址
        for ipa in ipre.findall(res_json):
            ww = ''
            ww = '.'.join(ipa)
            for ip_temp in ip_local:
                if ip_temp not in ww:
                    ip_list.append(ww)

    if urlre.findall(res_json):  # 导入http[s]url
        for urla in urlre.findall(res_json):
            for url_temp in ip_local:
                if url_temp not in urla[0]:
                    url_list.append(urla[0])

    if urlhttpre.findall(res_json):  # 导入url
        for urla in urlhttpre.findall(res_json):
            ww = ''
            for tup in urla:
                ww = ww + tup
                aa = ww.split('\\')
                ww = aa[0]
            url_list.append(ww)

    if mailre.findall(res_json):  # 导入邮箱
        for mail in mailre.findall(res_json):
            mail_list.append(mail)

    # 删除列表中重复的元素
    dll_list = string_duplicate_4(dll_list)
    ip_list = string_duplicate_4(ip_list)
    url_list = string_duplicate_4(url_list)
    mail_list = string_duplicate_4(mail_list)

    # 导入结果到Neo4
    start_node = Node("Malware", name=filename)
    g.merge(start_node, 'Malware', "name")

    for dll_item in dll_list:  # 创建dll
        dll_node = Node("DLL", name=dll_item)
        dll_relation = Relationship(start_node, 'DLL', dll_node)
        g.merge(dll_node, "DLL", "name")
        g.merge(dll_relation, "DLL", "name")

    for ip_item in ip_list:  # 创建ip
        ip_node = Node("IP", name=ip_item)
        ip_relation = Relationship(start_node, 'IP', ip_node)
        g.merge(ip_node, "IP", "name")
        g.merge(ip_relation, "IP", "name")

    for url_item in ip_list:  # 创建url
        url_node = Node("URL", name=url_item)
        url_relation = Relationship(start_node, 'URL', url_node)
        g.merge(url_node, "URL", "name")
        g.merge(url_relation, "URL", "name")

    for mail_item in mail_list:  # 创建mail
        mail_node = Node("Mail", name=mail_item)
        mail_relation = Relationship(start_node, 'Mail', mail_node)
        g.merge(mail_node, "Mail", "name")
        g.merge(mail_relation, "Mail", "name")

    # 导入结果到知识图谱
    save_to_kg(res_json, filename)
