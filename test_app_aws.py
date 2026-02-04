from moto import mock_aws
from app import app, init_aws_resources

def run_mock_aws_app():
    table, topic_arn = init_aws_resources()

    print("✅ Mock AWS running")
    print("📦 DynamoDB Table:", table.name)
    print("📣 SNS Topic:", topic_arn)

    app.run(debug=True)

if __name__ == "__main__":
    with mock_aws():
        run_mock_aws_app()
