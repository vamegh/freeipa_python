#!/usr/bin/python
#
##
##########################################################################
#                                                                        #
#       freeipa/ipa_dns                                                  #
#                                                                        #
#       freeipa_python (c) 2016 Vamegh Hedayati                          #
#                                                                        #
#       Vamegh Hedayati <gh_vhedayati AT ev9 DOT eu>                     #
#                                                                        #
#       Please see Copying for License Information                       #
#                             GNU/LGPL v2.1 1999                         #
##########################################################################
##
#

import json
import re
import requests
import socket
import sys
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

class DNS(object):
  def __init__(self, config=''):
    try:
      self.i_user = config["login_user"]
    except KeyError as e:
      print ('''Configurations should be passed as a dict,
                containing at least the login_pass, login_user and ipa_host key/values,
                optional: api_version, ssl_cert, ssl_key and ssl_verify can also be provided''')
      sys.exit(1)
    try:
      self.i_pass = config["login_pass"]
    except KeyError as e:
      print ('''Configurations should be passed as a dict,
                containing at least the login_pass, login_user and ipa_host key/values,
                optional: api_version, ssl_cert, ssl_key and ssl_verify can also be provided''')
      sys.exit(1)
    try:
      self.i_host = config["ipa_host"]
    except KeyError as e:
      print ('''Configurations should be passed as a dict,
                containing at least the login_pass, login_user and ipa_host key/values,
                optional: api_version, ssl_cert, ssl_key and ssl_verify can also be provided''')
      sys.exit(1)
    try:
      self.api_ver = config["api_version"]
    except KeyError as e:
      self.api_ver = "2.112"
    try:
      self.cert_file = config["ssl_cert"]
    except KeyError as e:
      self.cert_file = "certs/freeipa.crt"
    try:
      self.key_file = config["ssl_key"]
    except KeyError as e:
      self.key_file = "certs/freeipa.key"
    try:
      self.verify = config["ssl_verify"]
    except KeyError as e:
      self.verify = False
    self.login_url = self.i_host + '/ipa/session/login_password'
    self.query_url = self.i_host + '/ipa/session/json'
    self.referer = self.i_host + '/ipa'
    self.auth_headers = {'Content-type': 'application/x-www-form-urlencoded' , 'accept': 'text/plain' , 'referer': self.referer}
    self.auth_payload = {'user': self.i_user, 'password': self.i_pass}
    self.query_headers = {'Content-type': 'application/json' , 'accept': 'application/json', 'referer': self.referer}
    self.ssl_certs = (self.cert_file, self.key_file)
    self.session = ''

  def login(self):
    try:
      self.session = requests.post(self.login_url, headers=self.auth_headers, data=self.auth_payload, verify=self.verify )
    except self.session.ConnectionError as e:
      print ("Connection error :: ", str(e))
      sys.exit(1)
    except self.session.HTTPError as e:
      print ("HTTP Response error :: ", str(e))
      sys.exit(1)
    except Exception as e:
      print ("login :: error :: ", str(e))
      sys.exit(1)
    except:
      print ("login :: error :: ", sys.exc_info()[0])
      raise
    status_code = self.session.status_code
    if status_code == 401:
      print ("Auth Error could not login using auth provided :: status:",status_code,":: user:",self.i_user)
      sys.exit(1)
    elif status_code ==500:
      print ("Internal Server Error -- Service probably down :: status :: ",status_code)
      sys.exit(1)
    #return self.session
    return "success"

  def zone_find(self, search=''):
    dnszone_payload = { "id": 0, "method": "dnszone_find", "params": [[search], {"version": self.api_ver}]}
    try:
      dns_zone_find = requests.post(self.query_url,
                                    headers=self.query_headers,
                                    cookies=self.session.cookies,
                                    verify=self.verify,
                                    json=(dnszone_payload))
    except Exception as e:
      print ("zone_find :: error :: ", str(e))
      sys.exit(1)
    except:
      print ("zone_find :: error :: ", sys.exc_info()[0])
      raise
    zone_response = dns_zone_find.json()
    for data in zone_response:
      if data == "result":
        if zone_response[data]:
          print ("Zone :: " + search + " :: Found :: Skipping Addition ")
        else:
          print ("Zone :: " + search + " :: Not Found ")
          return "fail"
    return "success"

  def zone_show(self, search=''):
    if not re.search(r'\.$',search):
      search = search + "."
    dnszone_payload = { "id": 0, "method": "dnszone_show", "params": [[{"__dns_name__": search}], {"version": self.api_ver}]}
    try:
      dns_zone_show = requests.post(self.query_url,
                                    headers=self.query_headers,
                                    cookies = self.session.cookies,
                                    verify=self.verify,
                                    json=(dnszone_payload))
    except Exception as e:
      print ("zone_show :: error :: ", str(e))
      sys.exit(1)
    except:
      print ("zone_show :: error :: ", sys.exc_info()[0])
      raise
    zone_response = dns_zone_show.json()
    for data in zone_response:
      if data == "result":
        if zone_response[data]:
          print ("Zone :: " + search + " :: Found :: Skipping Addition ")
        else:
          print ("Zone :: " + search + " :: Not Found ")
          return "fail"
    return "success"

  def zone_add(self, search=''):
    if not re.search(r'\.$',search):
      search = search + "."
    dnszone_payload = { "id": 0, "method": "dnszone_add", "params": [
                        [ { "__dns_name__": search } ],
                        {"dnsttl": 60, "idnsallowdynupdate": 'true',
                         "idnsallowsyncptr": 'true',
                         "version": self.api_ver }]}
    try:
      dns_zone_add = requests.post(self.query_url,
                                   headers=self.query_headers,
                                   cookies = self.session.cookies,
                                   verify=self.verify,
                                   json=(dnszone_payload))
    except Exception as e:
      print ("zone_add :: error :: ", str(e))
      sys.exit(1)
    except:
      print ("zone_add :: error :: ", sys.exc_info()[0])
      raise
    zone_response = dns_zone_add.json()
    for data in zone_response:
      if data == "result":
        if zone_response[data]:
          for results in zone_response[data]["result"]:
            print ("Zone :: " + search + " :: Added :: results =", results)
        else:
          print ("Zone :: " + search + " :: Probably failed  -- Error Message :: ", zone_response['error']['message'])
          return "fail"
    return "success"

  def rev_record_add(self, host_data='', zone='', record='', data=''):
    if host_data:
      zone=host_data['rev_zone']
      data=host_data['ext_fqdn']
      record=host_data['rev_ip']
    if not re.search(r'\.$',zone):
      zone = zone + "."
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_add", "params": [
                        [{ "__dns_name__": zone }, { "__dns_name__": record }],
                        {"ptr_part_hostname": { "__dns_name__": data },
                         "version": self.api_ver }]}

    try:
      dns_record_add = requests.post(self.query_url,
                                     headers=self.query_headers,
                                     cookies=self.session.cookies,
                                     verify=self.verify,
                                     json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_add.json()
    for data in record_response:
      if data == "result":
        if record_response[data]:
          for results in record_response[data]["result"]:
            print ("DNS Record zone :: " + zone + " :: record :: " +record+ " :: data :: " +data+ " Added :: results: "+results)
        else:
          print ("DNS Record zone :: " + zone + record + data + " :: Probably failed  -- Error Message :: ", record_response['error']['message'])
          return "fail"
    return "success"

  def record_add(self, host_data='', zone='', record='', ip=''):
    if host_data:
      zone=host_data['dom_name']
      record=host_data['name']
    if not re.search(r'\.$',zone):
      zone = zone + "."
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_add", "params": [
                        [{ "__dns_name__": zone }, { "__dns_name__": record }],
                        {"arecord": [ ip ],
                         "version": self.api_ver }]}
    try:
      dns_record_add = requests.post(self.query_url,
                                     headers=self.query_headers,
                                     cookies=self.session.cookies,
                                     verify=self.verify,
                                     json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_add.json()
    for data in record_response:
      if data == "result":
        if record_response[data]:
          for results in record_response[data]["result"]:
            print ("DNS Record zone :: " + zone + " :: record :: " +record+ " :: ip :: " +ip+ " Added :: results: "+results)
        else:
          print ("DNS Record Addition :: zone: " +zone+ " :: record: " +record+ " :: ip: " +ip+ " :: Probably failed  -- Error Message :: ", record_response['error']['message'])
          return "fail"
    return "success"

  def record_del(self, host_data='', zone='', record='', ip=''):
    if host_data:
      zone=host_data['dom_name']
      record=host_data['name']
    if not re.search(r'\.$',zone):
      zone = zone + "."
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_del", "params": [
                        [{ "__dns_name__": zone }, { "__dns_name__": record }],
                        {"del_all": "false",
                         "arecord": [ ip ],
                         "version": self.api_ver }]}

    try:
      dns_record_del = requests.post(self.query_url,
                                     headers=self.query_headers,
                                     cookies=self.session.cookies,
                                     verify=self.verify,
                                     json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_del.json()
    for data in record_response:
      if data == "result":
        if record_response[data]:
          if record_response[data]["summary"]:
            results = record_response[data]["summary"]
            print ("DNS Record zone :: " + zone + " :: record :: "
                   +record+ " :: ip :: " +ip+ " Deleted :: results: "+results)
        else:
          print ("DNS Record deletion :: zone: " +zone+ " :: record: "
                 +record+ " :: ip: " +ip+ " :: Probably failed  -- Error Message :: ",
                 record_response['error']['message'])
          return "fail"
    return "success"

  def rev_record_del(self, host_data='', zone='', record='', rev_data=''):
    if host_data:
      zone=host_data['rev_zone']
      rev_data=host_data['ext_fqdn']
      record=host_data['rev_ip']
    if not re.search(r'\.$',zone):
      zone = zone + "."
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_del", "params": [
                        [{ "__dns_name__": zone }, { "__dns_name__": record }],
                        {"del_all": "false",
                         "ptrrecord": [ rev_data ],
                          "version": self.api_ver }]}
    try:
      dns_record_del = requests.post(self.query_url,
                                     headers=self.query_headers,
                                     cookies=self.session.cookies,
                                     verify=self.verify,
                                     json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_del.json()
    for data in record_response:
      if data == "result":
        if record_response[data]:
          if record_response[data]["summary"]:
            results = record_response[data]["summary"]
            print ("DNS Reverse Record zone :: " + zone + " :: record :: "
                   +record + " :: data :: " +data+ " Deleted :: results: "+results)
        else:
          print ("DNS Reverse Record deletion :: zone: " +zone+ " :: record: "
                 +record+ " :: data: " +data+ " :: Probably failed  -- Error Message :: ",
                 record_response['error']['message'])
          return "fail"
    return "success"

  def record_show(self, host_data='', search_zone='', search_record=''):
    if host_data:
      search_zone=host_data['dom_name']
      search_record=host_data['name']
    if not re.search(r'\.$',search_zone):
      search_zone = search_zone + "."
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_show",
                          "params": [[{"__dns_name__": search_zone},
                                      {"__dns_name__": search_record}],
                                      {"version": self.api_ver}]}
    try:
      dns_record_find = requests.post(self.query_url,
                                      headers=self.query_headers,
                                      cookies = self.session.cookies,
                                      verify=self.verify,
                                      json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_find.json()
    ip_entries = []
    ip_rev_entries = []
    count=''
    if record_response["result"]:
      try:
        ip_entries = record_response["result"]["result"]["arecord"]
      except  KeyError as e:
        '''print "skipping entry", e'''
      try:
        ip_rev_entries = record_response["result"]["result"]["ptrrecord"]
      except  KeyError as e:
        '''print "skipping entry", e'''
    else:
      print ("Zone :: " +search_zone+ " record :: " +search_record+ " :: Not Found ")
      return ip_entries, ip_rev_entries, record_response
    return ip_entries, ip_rev_entries,record_response

  def host_record_find(self, host_data='', search_zone='', search_record=''):
    if host_data:
      search_zone=host_data['dom_name']
      search_record=host_data['name']
    if not re.search(r'\.$',search_zone):
      search_zone = search_zone + "."
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_find",
                          "params": [[{"__dns_name__": search_zone},{}],
                          {"idnsname": {"__dns_name__": search_record},
                          "version": self.api_ver}]}
    try:
      dns_record_find = requests.post(self.query_url,
                                      headers=self.query_headers,
                                      cookies = self.session.cookies,
                                      verify=self.verify,
                                      json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_find.json()
    ip_entries = []
    ip_rev_entries = []
    count=''
    if record_response["result"]:
      for data in record_response["result"]:
        if data == "result":
          if record_response[data]:
            for results in record_response[data]["result"]:
              try:
               ip_entries = results["arecord"]
              except  KeyError as e:
                '''print "skipping entry", e'''
              try:
               ip_rev_entries = results["ptrrecord"]
              except  KeyError as e:
                '''print "skipping entry", e'''
          else:
            print ("Zone :: " +search_zone+ " record :: " +search_record+ " :: Not Found ")
            return ip_entries, ip_rev_entries, record_response
    else:
      print ("Zone :: " +search_zone+ " Record Not Found ")
    return ip_entries, ip_rev_entries,record_response

  def record_find(self, host_data='', search_zone='', search_record=''):
    if host_data:
      search_zone=host_data['dom_name']
      search_record=host_data['name']
    if not re.search(r'\.$',search_zone):
      search_zone = search_zone + "."
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_find",
                          "params": [[{ "__dns_name__": search_zone },search_record],
                          {"version": self.api_ver}]}
    try:
      dns_record_find = requests.post(self.query_url,
                                      headers=self.query_headers,
                                      cookies = self.session.cookies,
                                      verify=self.verify,
                                      json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_find.json()
    ip_entries = []
    ip_rev_entries = []
    count=''
    if record_response["result"]:
      for data in record_response["result"]:
        if data == "result":
          if record_response[data]:
            for results in record_response[data]["result"]:
              try:
               ip_entries = results["arecord"]
              except  KeyError as e:
                '''print "skipping entry", e'''
              try:
               ip_rev_entries = results["ptrrecord"]
              except  KeyError as e:
                '''print "skipping entry", e'''
          else:
            print ("Zone :: " +search_zone+ " record :: " +search_record+ " :: Not Found ")
            return ip_entries, ip_rev_entries, record_response
    else:
      print ("Zone :: " +search_zone+ " Record Not Found ")
    return ip_entries, ip_rev_entries,record_response


  def all_record_find(self, search='', ip=''):
    dnsrecord_payload = { "id": 0, "method": "dnsrecord_find",
                          "params": [[{"__dns_name__": search},{}],
                          {"version": self.api_ver}]}
    try:
      dns_record_find = requests.post(self.query_url,
                                      headers=self.query_headers,
                                      cookies=self.session.cookies,
                                      verify=self.verify,
                                      json=(dnsrecord_payload))
    except Exception as e:
      print ("error :: ", str(e))
      sys.exit(1)
    except:
      print ("error :: ", sys.exc_info()[0])
      raise
    record_response = dns_record_find.json()
    pointer = []
    ip_entries = []
    count=''
    address = str(ip)
    ip_octs = address.split(".")
    ips_used = []
    record_count = ''
    for data in record_response["result"]:
      if data == "result":
        if record_response[data]:
          for results in record_response[data]["result"]:
            try:
             pointer.append(results["ptrrecord"])
             ip_entries.append(results["idnsname"][0]["__dns_name__"])
            except  KeyError as e:
              '''print "skipping entry", e'''
          record_count = record_response[data]["count"]
          for ip_addy in ip_entries:
            ips_used.append(ip_octs[0] +"."+ ip_octs[1] +"."+ ip_octs[2] +"."+ ip_addy)
        else:
          print ("Zone: " + search + " ip: "+ip+ " :: Not Found ")
          return record_count, pointer, ips_used, record_response
    return record_count, pointer, ips_used, record_response

