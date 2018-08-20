from django.db import models
from django.contrib.postgres.fields import JSONField


def address_field():
    return {'house':'', 'street':'', 'lm':'', 'vtc':'', 'subdist':'', 'dist':'',
            'state':'', 'country':'', 'pc':'', 'po':''}

    
def laddress_field():
    return {'house':'', 'street':'', 'lm':'', 'loc':'', 'vtc':'', 'subdist':'',
            'dist':'', 'state':'', 'country':'', 'pc':'', 'po':''}


def ASA_data():
    return {'AUAList':[]}


class Resident(models.Model):
    uid = models.CharField(max_length=12, primary_key=True)
    auth_status = models.CharField(max_length=1, default='T')
    lang_code = models.CharField(max_length=2, blank=True)
    PIN = models.CharField(max_length=6, blank=True)
    name = models.CharField(max_length=60, blank=True)
    lname = models.CharField(max_length=80, blank=True)
    gender = models.CharField(max_length=1, blank=True)
    dob = models.CharField(max_length=10, blank=True)
    phone = models.CharField(max_length=15, blank=True)
    isVerified = models.CharField(max_length=2, default='00')
    # Phone # Email
    email = models.CharField(max_length=100, blank=True)
    # cant give default as a non callable
    address = JSONField(default=address_field, blank=True)
    laddress = JSONField(default=laddress_field, blank=True)
    # lm = landmark
    # loc = locality
    # vtc = village/town/city
    # pc = postal pin code
    # po = postal office name
    care_of = models.CharField(max_length=60, blank=True)
    lcare_of = models.CharField(max_length=80, blank=True)
    photo = models.ImageField(blank=True)
    bios = JSONField(default=dict)

    def __str__(self):
        return self.uid


class ASA(models.Model):
    asaID = models.CharField(max_length=10)
    asalk = models.CharField(max_length=100)
    Data = JSONField(default=ASA_data)

    def __str__(self):
        return self.asaID


class AUA(models.Model):
    auaID = models.CharField(max_length=20)
    asa = models.ForeignKey(ASA,on_delete = models.CASCADE,default=None)
    Data = JSONField(default=dict)
    # Pi,Pa,Pfa,FMR,FIR,IIR,OTP,PIN,FUZZY,LOCAL_LANGUAGE
    # 1111111001
    def __str__(self):
        return self.auaID


class AuthenticateRouter(object):
    def db_for_read(self, model, **hints):
        if model._meta.app_label == 'authenticate':
            return 'niraadhaardb'
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == 'authenticate':
            return 'niraadhaardb'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label == 'authenticate' or \
           obj2._meta.app_label == 'authenticate':
           return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == 'authenticate':
            return db == 'niraadhaardb'
        return None
