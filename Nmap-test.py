from flask import Flask, render_template, request, jsonify
import nmap

app = Flask(__name__)

def scan_ports(host, ports):
    """
    扫描指定主机和端口范围，并返回扫描结果。

    :param host: 要扫描的主机地址
    :param ports: 要扫描的端口范围（例如 '1-1024'）
    :return: 扫描结果的字典
    """
    try:
        # 创建扫描器对象
        nm = nmap.PortScanner()

        # 扫描指定主机和端口范围
        nm.scan(host, ports)

        # 构建扫描结果的字典
        scan_results = {}
        if nm.all_hosts():
            for h in nm.all_hosts():
                ports_info = []
                for proto in nm[h].all_protocols():
                    for port in nm[h][proto]:
                        port_info = {
                            'port': port,
                            'protocol': proto,
                            'state': nm[h][proto][port]['state']
                        }
                        ports_info.append(port_info)
                scan_results[h] = ports_info
        else:
            scan_results['error'] = f"主机 {host} 不可达"

        return scan_results

    except nmap.PortScannerError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def do_scan():
    data = request.get_json()
    host = data['host']
    ports = data['ports']

    # 调用扫描函数
    results = scan_ports(host, ports)
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
