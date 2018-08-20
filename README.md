It's an implementation aimed at mimicking the working of Aadhaar's Authentication and eKYC APIs to use on local environment.

# Running Instructions - 
1. Create postgres and redis
```bash
cd db_containers
docker-compose up -d 
```
2. Change Dir to NirAadhaar_Server
```bash
cd NirAadhaar_Server
```

3. Install python dependencies
```bash
pipenv install
```

4. Activate pipenv
```bash
pipenv shell
```

5. Migrate Django Models & Authenticate
```bash
python manage.py migrate # migrates django models to a sqlite3 db
python manage.py makemigrations authenticate # make migrations for authenticate app
python manage.py migrate --database niraadhaardb # migrate other models to postgresql
```

6. Run Server
```bash
python manage.py runserver 0.0.0.0:8000 # starts NirAadhaar server at all IPs that the host pc is connected to
```

# Indexing AUA, ASA and Residents
Aadhaar uses AUAs and ASAs in order to regulate which end points can have access to their database.
We should replicate this functionality as well.

navigate to-
```
http://localhost:8000/admin
```
Enter super user, username and password.

Add an ASA with info as-
```json
{
    "AsaID": "TEST_ASA",
    "Asalk": "TEST_ASALK",
    "Data": {"AUAList": ["TEST_AUA"]}
}
```

Add an AUA with info as-
```json
{
    "AuaID": "TEST_AUA",
    "Asa": "TEST_ASA",
    "Data": { "privateKey": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBMDRia29rc1FTS0pEMXJvWmVRVjJ2YjNOT29XcGFMYnp3RDJNVHR6cHpZQUhFWjlSCnE5ZXRqMVBCQmhrZnpsV293TnUvNWloU1MxSkREWnRQd1NzQlJRejhvVHg4WlFSaTl2N3FoODlUaVprVFdyelkKekE5N2UwRWZoYkJCeTZsNGV3WXQ4NVJiZWk5TWxZV3R4TEQ5Z0Z0QlQxWHIrSXNaMldvcnMyMTBrc2Vxemkzdworb0NGanloVWJNRG4yMm1BOUV2VVZLQ1RraEVTWDJ2OXFKSHpTY1YzNVJic2FNWmlLTlNFTDlzY3YwMXQzU2h5CkpKVnlPS1RWcU9iQW9FUVRTaGRMbzUzTkpDci96b3FMR0pxMUtHNXBoTkZ2dmdtLzliVjIwZXA0SGZ5ZkE1c2QKcERFNmt1eEhUQzV3OUxrdFNBN29TSzcrRFFuNDlIaEJXangvTFFJREFRQUJBb0lCQUV5a2ViOGNONkE1dXg3WQplMVpRVm4vVmY4RU9vUjFoL052UThUKzU1N1VnQ0crb0xHMTVUbGU2WHh3WWlsKzJ4ZGhyUnhMYjFVV1pYdFpWClNnYVIwSG4yaEtyZlFhdFFkWk5OTmlsVFE4OTllWGZOS1RoMis2VGpLY3JFM0hJd3k0aTM2bnB4Yk52T3U0OEoKeXJhVDhxWkphbGFXcVZON0F6aTFzWFBuMnU4N1pIRFBDd3FFUWpWVFBGcmxUZG9mRzNUaHp5eS80UlV2U1kvMgorZVdyVVBrajIvZzE2UEFpY2FHQnlpNHZNdWVqWi9FQlJscG1LeHNqSXFtcG9CRHpRZVVvcDRsQXNxWkdqNTNEClFNUEdsTEw3MjJYby9BaUhFUC80Rm9zZDg0cnhpK1JYdmw0L2JoRzdNKzJ3ZEpyYUVwb1NKSUFZTlYzdEs3eU4KYmt2RFo0RUNnWUVBK1FYOFRSenQyRlNpL2dtcXlRbW0xUElzZWErdm1WZVRxN3QySzVVYnFUNXJMazJ2dGxlaAovTTBKOUo2TWRLZXBBckdjWlM0RTc3TS9XWUtPcWl4bGtHU2xRRWUyTjRrSGt5ZEdTcm5NRW5URjJzSndCRU1ICjVSTWxGaXhCOTV6K3VTcm9PQUJuK3Z0OFY0Q1FpcVVyZ2g3aE05Y29aUjZ0ZFgwSFVBTG5wSkVDZ1lFQTJYUDYKNnljVmNJUU5PTDBRK3c0VVNXM2FEZ0kwZ296djUvbDlMM080b0l0Vk91aENtK0ZJUVZueGRnK0RlSG00NkJmWgpLVno1NHVpWk1SQmVxcm1iUUhYeDVaQUpzaDhVOVRMMFVUTGt0WjJ1Wlk3SG1idzRFTmVrWVkrdWdyR0pYczdPClZsSUc2VFFjZEVLQXZzdkRGUmRSUy9tdDNlSW0yYnk2TXh6TGp0MENnWUFHV1crNGE1OW8zNmVVUUp6WktXVFcKa3lJdExCeVhGVk9Qa21VTjhXeFdJV0JNT3ZEYS9sc0QvaHBkNFZrRmRHenJ3Nm1RTHQ4eldXZXBHWm9YbnJBcwpRVlN4VWVMRWdicnV0cGFsT3gySDd2QklocUtpaVM3L1dVQ2QweDBQZWpKSWVGNlpadkUveGYvQ24yV1FFMndMCmtrdjlyV083U0UvMTZlMHd6aEluOFFLQmdRQzlLcnY1blVKMVl5cnRWT3hVdW1iRGlpRExWdmUvS2tQNWxYeGwKcjFISnQrd3BGcXY3VnZ1NGZqb2o3bEw4bDBkWUFJY1dDS0FKMlRhTERDYU9kbkNzbnU0VU9qMTFDcno4b1pzUQptQ21HSk9uMXgwTzBaWnlRYWtmQjUzQjBtV1ZiYUtUdlN1UmdNc2tlQ2t4ZHJuekMrRW5zd2dPU3BvNE5sTFNXCmlsSTZzUUtCZ1FDanEvK0RLbmVlSDNFQzl3bjIrYnZlTy9QcDhqdlFGUmltTVE4Q2IzUWRad0M5NG9XSFpLeWoKVVJ4WU1HOXZPNkxlNlN2cUJncS8rZ3NsdVRXbUMrdHpBU2JYbkpLbUJxZlU3cFp4ZlNPVlFtUGRmQUt0SmFvSwp1U2lnQksyeWlMSzdhMXBwNVQvVnVHdXlBSFd3cWNsVHNEZzlUa0Y1WjBpRHVXL1VOMEhURlE9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=", "LicenseRights": "1111111111"}
```



Add any Aadhaar card's data in the format of SampleAUA/Input_Template.json To Resident Table.
For reference on meaning of fields see SampleAUA/Input.json

for sample requests to NirAadhaar Server See SampleAUA module.

```python
from SampleAUA import OTPInit
# It might or might not send OTP to the number, configure your own SMS Gateway or use the way2sms script in OTPgen/views.py/sendSMSto
OTPInit('11', 'AADHAAR_NUMBER_OF_REGISTERD_RESIDENT')
# 11 = send sms and mail both
eKYCInit("JSONInfo based on Input Template [just fill the uid field after importing the json]", "OTP received by the consumer")
# it will either return the error else the saved information of the person
```