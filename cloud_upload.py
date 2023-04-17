import boto3
from botocore.exceptions import NoCredentialsError

ACCESS_KEY = 'AKIA524WMMC23Y5JERQH'
SECRET_KEY = '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'
s3 = boto3.client('s3', aws_access_key_id=ACCESS_KEY,
                      aws_secret_access_key=SECRET_KEY)

def upload_to_aws(local_file, bucket, s3_file):
    """
    Upload local file into amazon s3 bucket.
    @param  local_file - local data file (image.jpg and text file)
            bucket - amazon s3 bucket name
            s3_file - riffile shuffled name.
    @return True - upload success
            False - error
    """

    try:
        s3.upload_file(local_file, bucket, s3_file)
        print("Upload Successful")
        return True
    except FileNotFoundError:
        print("The file was not found")
        return False
    except NoCredentialsError:
        print("Credentials not available")
        return False

def download_from_aws(file_name,dest_path):
    s3.download_file('cloudbucketaleena',file_name,dest_path)

def load_shuffle_data():
    package_name = []
    version = []

    packages_file = open('log/riffle_shuffle.txt', 'r')
    for line_info in packages_file:
        dat = line_info.split(':')
            # Modified for 3.0
            # Porting to python 3.8
            #
        if("'" in dat[0]):
            v = dat[0]
            splt = v.split('\'')
            dat[0] = splt[1]
             #End of modification for 3.0
        package_name.append(dat[0])
        version.append(dat[1])
    packages_file.close()
    #print(package_name)
    #print(version)
    return package_name , version
    #os.remove('./src/names.txt')
