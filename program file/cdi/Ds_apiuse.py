from openai import OpenAI

# 使用环境变量管理 API 密钥
api_key = ''
if not api_key:
    raise ValueError("请设置环境变量 OPENAI_API_KEY")

# 提取常量
BASE_URL = "https://api.deepseek.com"
MODEL_NAME = "deepseek-chat"

client = OpenAI(api_key=api_key, base_url=BASE_URL)

try:
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": "Hello"},
        ],
        stream=False
    )
    print(response.choices[0].message.content)
except Exception as e:
    print(f"发生错误: {e}")
