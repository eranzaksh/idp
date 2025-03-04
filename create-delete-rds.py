import boto3
import json

def lambda_handler(event, context):
    # Extract action and user input from the event
    action = event.get('action', 'create')
    db_identifier = event.get('db_identifier')

    # Initialize RDS client
    rds_client = boto3.client('rds')

    try:
        if action == 'create':
            db_username = event.get('db_username')
            db_password = event.get('db_password')

            # Create RDS instance
            response = rds_client.create_db_instance(
                DBName='ExampleDB',
                DBInstanceIdentifier=db_identifier,
                AllocatedStorage=20,
                DBInstanceClass='db.t4g.micro',
                Engine='mysql',
                MasterUsername=db_username,
                MasterUserPassword=db_password,
                VpcSecurityGroupIds=['sg-021784efb1b63515e'],
                PubliclyAccessible=False
            )

            return {
                'statusCode': 200,
                'body': json.dumps('RDS instance creation initiated. Instance ID: ' + response['DBInstance']['DBInstanceIdentifier'])
            }
        elif action == 'delete':
            # Delete RDS instance
            response = rds_client.delete_db_instance(
                DBInstanceIdentifier=db_identifier,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True
            )

            return {
                'statusCode': 200,
                'body': json.dumps('RDS instance deletion initiated. Instance ID: ' + response['DBInstance']['DBInstanceIdentifier'])
            }
        else:
            return {
                'statusCode': 400,
                'body': json.dumps('Invalid action')
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error performing {action} operation on RDS instance: ' + str(e))
        }
