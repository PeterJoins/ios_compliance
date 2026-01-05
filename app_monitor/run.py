from app import create_app, socketio
from config import Config

app = create_app()

if __name__ == '__main__':
    print("[-] WebSocket 服务启动中: http://127.0.0.1:8080")
    # 使用 socketio.run 启动
    socketio.run(app, host='0.0.0.0', port=Config.SERVER_PORT, debug=True)