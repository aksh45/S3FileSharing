from app.main import app
 
if __name__ == "__main__":
    from waitress import serve
    app.run(host="0.0.0.0",port=8080,ssl_context='adhoc')
