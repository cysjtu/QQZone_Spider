# -*- coding: utf-8 -*-
'''
QQ Zone Login module
Maintainer: CY  ( 1471242852@qq.com )
Last change: 2015.6.16
'''
import time
import hashlib, re,  binascii, base64
import rsa, requests
import tea
import datetime
from selenium import webdriver
import urllib
import MySQLdb
from BeautifulSoup import BeautifulSoup
import MySQLdb.cursors
import sys




class QQ:
    appid = 549000912
    action = '3-13-1434448250171'
    xlogin = 'http://xui.ptlogin2.qq.com/cgi-bin/xlogin'
    checkurl = 'http://check.ptlogin2.qq.com/check'
    imgurl = 'http://captcha.qq.com/getimage'
    loginurl = 'http://ptlogin2.qq.com/login'
    logo="http://qlogo2.store.qq.com/qzone/576033717/576033717/100"

    pubKey = rsa.PublicKey(int(
        'F20CE00BAE5361F8FA3AE9CEFA495362'
        'FF7DA1BA628F64A347F0A8C012BF0B25'
        '4A30CD92ABFFE7A6EE0DC424CB6166F8'
        '819EFA5BCCB20EDFB4AD02E412CCF579'
        'B1CA711D55B8B0B3AEB60153D5E0693A'
        '2A86F3167D7847A0CB8B00004716A909'
        '5D9BADC977CBB804DBDCBA6029A97108'
        '69A453F27DFDDF83C016D928B3CBF4C7',
        16
    ), 3)



    def __init__(self, user, pwd):
        self.user = user
        self.pwd = pwd
        self.conn=MySQLdb.connect(host="127.0.0.1",user="root",passwd="",port=3306,db="book",charset='utf8',cursorclass = MySQLdb.cursors.DictCursor)
        self.cur=self.conn.cursor()


        self.webdriver=webdriver.Firefox()
        self.login()
        print "### init & login finish....###"

    def __del__(self):
        self.webdriver.close()
        #self.webdriver.quit()
        self.conn.close()


    def login(self):

        #xlogin
        params={
            'appid': self.appid,
            'daid': 5,
            'hide_title_bar': 1,
            'link_target': 'blank',
            'low_login': 0,
            'no_verifyimg': 1,
            'proxy_url': 'http://qzs.qq.com/qzone/v6/portal/proxy.html',
            'pt_qr_app': '手机QQ空间',
            'pt_qr_help_link': 'http://z.qzone.com/download.html',
            'pt_qr_link': 'http://z.qzone.com/download.html',
            'pt_qzone_sig': 1,
            'qlogin_auto_login': 1,
            's_url': 'http://qzs.qq.com/qzone/v5/loginsucc.html?para=izone',
            'self_regurl': 'http://qzs.qq.com/qzone/v6/reg/index.html',
            'style': 22,
            'target': 'self'
        }
        url1=self.xlogin+"?%s" %urllib.urlencode(params)
        self.webdriver.get(url1)
        #print "###xlogin %s" %url1

        self.login_sig = self.webdriver.get_cookie('pt_login_sig')['value']


        #check
        params={
            'appid': self.appid,
            'js_type': 1,
            'js_ver': 10126,
            'login_sig': self.login_sig,
            'pt_tea': 1,
            'pt_vcode': 1,
            'r': 0.6914938215631992,
            'regmaster': '',
            'u1': 'http://qzs.qq.com/qzone/v5/loginsucc.html?para=izone',
            'uin': self.user
        }

        url2=self.checkurl+"?%s" %urllib.urlencode(params)
        self.webdriver.get(url2)
        #print "###check %s" %url2

        v = re.findall('\'(.*?)\'', self.webdriver.page_source)
        self.vcode = v[1]
        self.uin = v[2]

        if v[0] == '1':  # verify code needed
            print "###need verify code "
            exit()

        self.ptvfsession = self.webdriver.get_cookie('ptvfsession')['value']

        # login now
        params={
            'action': '3-13-1434448250171',
            'aid': 549000912,
            'daid': 5,
            'from_ui': 1,
            'g': 1,
            'h': 1,
            'js_type': 1,
            'js_ver': 10126,
            'login_sig': self.login_sig,
            'p': self.pwdencode(self.vcode, self.uin, self.pwd),
            'pt_qzone_sig': 1,
            'pt_randsalt': 0,
            'pt_uistyle': 32,
            'pt_vcode_v1': 0,
            'pt_verifysession_v1': self.ptvfsession,
            'ptlang': 2052,
            'ptredirect': 0,
            't': 1,
            'u': self.user,
            'u1': 'http://qzs.qq.com/qzone/v5/loginsucc.html?para=izone',
            'verifycode': self.vcode
        }

        url3=self.loginurl+"?%s" %urllib.urlencode(params)
        self.webdriver.get(url3)
        #print "###login %s" %url3

        r = re.findall('\'(.*?)\'', self.webdriver.page_source)
        if r[0] != '0':
            print "login error "
            exit()

        self.ptsig=re.findall('ptsig=(.*)',r[2])
        self.webdriver.get(r[2])

        #print "###login success"



    def fromhex(self, s):
        # Python 3: bytes.fromhex
        return bytes(bytearray.fromhex(s))

    def pwdencode(self, vcode, uin, pwd):
        # uin is the bytes of QQ number stored in unsigned long (8 bytes)
        salt = uin.replace(r'\x', '')
        h1 = hashlib.md5(pwd.encode()).digest()
        s2 = hashlib.md5(h1 + self.fromhex(salt)).hexdigest().upper()
        rsaH1 = binascii.b2a_hex(rsa.encrypt(h1, self.pubKey)).decode()
        rsaH1Len = hex(len(rsaH1) // 2)[2:]
        hexVcode = binascii.b2a_hex(vcode.upper().encode()).decode()
        vcodeLen = hex(len(hexVcode) // 2)[2:]
        l = len(vcodeLen)
        if l < 4:
            vcodeLen = '0' * (4 - l) + vcodeLen
        l = len(rsaH1Len)
        if l < 4:
            rsaH1Len = '0' * (4 - l) + rsaH1Len
        pwd1 = rsaH1Len + rsaH1 + salt + vcodeLen + hexVcode
        saltPwd = base64.b64encode(
            tea.encrypt(self.fromhex(pwd1), self.fromhex(s2))
        ).decode().replace('/', '-').replace('+', '*').replace('=', '_')
        return saltPwd

    def getVerifyCode(self, vcode):

        params={
            'r': 0,
            'appid': self.appid,
            'uin': self.user,
            'vc_type': vcode,
        }
        url=self.imgurl+"?%s" % urllib.urlencode(params)
        self.webdriver.get(url)
        vcode = raw_input('Verify code: ')
        return vcode









    #parent_qq="",qq="",head_picture="",last_modify="",name="",sex="",address="",age="",birthday="",star=""
    def add_friend(self,arg):
        print "@@@add_friend\n\r"
        #print arg['parent_qq']
        #print arg['qq']
        arg['head_picture']="http://qlogo2.store.qq.com/qzone/%s/%s/100"%(arg['qq'],arg['qq'])
        arg['last_modify']=str(int(time.time()))



        self.cur.execute("select count(*) from qq_friends where parent_qq=\'%s\' and qq=\'%s\'"%(arg['parent_qq'],arg['qq']))

        cnt=self.cur.fetchall()[0]['count(*)']

        for i in arg:
            if arg[i] is None:
                arg[i]="none"

        if cnt==0:

            keys=",".join( i for i in arg)

            #print keys

            values="\",\"".join( arg[i].replace("\""," ") for i in arg)
            values='\"'+values+'\"'
            #print values

            exe="insert into qq_friends(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()
        elif cnt==1:
            self.cur.execute("select * from qq_friends where parent_qq=\'%s\' and qq=\'%s\'"%(arg['parent_qq'],arg['qq']))
            friend=self.cur.fetchall()
            #print friend[0]
            dic={}
            for i in friend[0]:
                dic[i]=friend[0][i]

            for i in arg:
                dic[i]=arg[i]



            keys=",".join( i for i in dic)

            #print keys

            values="\",\"".join( dic[i].replace("\""," ") for i in dic)
            values='\"'+values+'\"'
            #print values

            self.cur.execute("delete  from qq_friends where parent_qq=\'%s\' and qq=\'%s\'"%(dic['parent_qq'],dic['qq']))
            self.conn.commit()

            exe="insert into qq_friends(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        else:
            print " error duplicate friends\n "
            exit()





    #sender_qq,time,contents,picture,comment_num,see_num,zan_num,switch_num
    def add_shuo_shuo(self,arg):
        print "@@@add_shuo_shuo\n\r"


        #print arg['sender_qq']
        #print arg['time']
        #print arg['contents']
        #print arg['comment_num']
        #print arg['see_num']
        #print arg['zan_num']
        #print arg['switch_num']

        exe="select count(*) from qq_shuoshuo where shuo_shuo_id=\"%s\" "%(arg['shuo_shuo_id'])
        #print exe
        self.cur.execute(exe)

        cnt=self.cur.fetchall()[0]['count(*)']

        for i in arg:
            if arg[i] is None:
                arg[i]="none"


        if cnt==0:
            keys=",".join( i for i in arg)

            #print keys

            values="\",\"".join( arg[i].replace("\""," ") for i in arg)
            values='\"'+values+'\"'
            #print values

            exe="insert into qq_shuoshuo(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        elif cnt==1:
            self.cur.execute("select * from qq_shuoshuo where shuo_shuo_id=\"%s\" "%(arg['shuo_shuo_id']))
            friend=self.cur.fetchall()
            #print friend[0]
            dic={}
            for i in friend[0]:
                dic[i]=friend[0][i]

            for i in arg:
                dic[i]=arg[i]

            keys=",".join( i for i in dic)

            #print keys

            values="\",\"".join( dic[i].replace("\""," ") for i in dic)
            values='\"'+values+'\"'
            #print values

            self.cur.execute("delete  from qq_shuoshuo where shuo_shuo_id=\"%s\" "%(arg['shuo_shuo_id']))
            self.conn.commit()

            exe="insert into qq_shuoshuo(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        else:
            print "shuo shuo duplicate\n"




    #host_qq,sender_qq,time,contents
    def add_liuyan(self,arg):
        print "@@@add_liuyan\n\r"
        #print arg['host_qq']
        #print arg['sender_qq']
        #print arg['time']
        #print arg['contents']
        for i in arg:
            if arg[i] is None:
                arg[i]="none"
        self.cur.execute("select count(*) from qq_liuyanban where host_qq=\'%s\' and liuyan_num=\'%s\'"%(arg['host_qq'],arg['liuyan_num']))

        cnt=self.cur.fetchall()[0]['count(*)']

        if cnt==0:
            keys=",".join( i for i in arg)

            #print keys

            values="\",\"".join( arg[i].replace("\""," ") for i in arg)
            values='\"'+values+'\"'
            #print values

            exe="insert into qq_liuyanban(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        elif cnt==1:
            self.cur.execute("select * from qq_liuyanban where host_qq=\'%s\' and liuyan_num=\'%s\'"%(arg['host_qq'],arg['liuyan_num']))
            friend=self.cur.fetchall()
            #print friend[0]
            dic={}
            for i in friend[0]:
                dic[i]=friend[0][i]

            for i in arg:
                dic[i]=arg[i]

            keys=",".join( i for i in dic)

            #print keys

            values="\",\"".join( dic[i].replace("\""," ") for i in dic)
            values='\"'+values+'\"'
            #print values

            self.cur.execute("delete  from qq_liuyanban where host_qq=\'%s\' and liuyan_num=\'%s\'"%(arg['host_qq'],arg['liuyan_num']))
            self.conn.commit()

            exe="insert into qq_liuyanban(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()


        else:
            print "liu yan duplicate\n"

    #bei_zan_qq,zan_qq,time,shuo_shuo_qq,shuo_shuo_time
    def add_zan(self,arg):
        print "@@@add_zan\n\r"
        #print arg['bei_zan_qq']
        #print arg['zan_qq']
        #print arg['time']
        for i in arg:
            if arg[i] is None:
                arg[i]="none"
        self.cur.execute("select count(*) from qq_zan where shuo_shuo_id=\'%s\' and zan_qq=\'%s\' "%(arg['shuo_shuo_id'],arg['zan_qq']))

        cnt=self.cur.fetchall()[0]['count(*)']

        if cnt==0:
            keys=",".join( i for i in arg)

            #print keys

            values="\",\"".join( arg[i].replace("\""," ") for i in arg)
            values='\"'+values+'\"'
            #print values

            exe="insert into qq_zan(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        elif cnt==1:
            self.cur.execute("select * from qq_zan where shuo_shuo_id=\'%s\' and zan_qq=\'%s\' "%(arg['shuo_shuo_id'],arg['zan_qq']))
            friend=self.cur.fetchall()
            #print friend[0]
            dic={}
            for i in friend[0]:
                dic[i]=friend[0][i]

            for i in arg:
                dic[i]=arg[i]

            keys=",".join( i for i in dic)

            #print keys

            values="\",\"".join( dic[i].replace("\""," ") for i in dic)
            values='\"'+values+'\"'
            #print values

            self.cur.execute("delete  from qq_zan where shuo_shuo_id=\'%s\' and zan_qq=\'%s\' "%(arg['shuo_shuo_id'],arg['zan_qq']))
            self.conn.commit()

            exe="insert into qq_zan(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()


        else:
            print "zan duplicate\n"



    #host_qq,comment_qq,time,shuo_shuo_qq,shuo_shuo_time,contents
    def add_comment(self,arg):
        print "@@@add_comment\n\r"
        #print arg['host_qq']
        #print arg['comment_qq']
        #print arg['time']
        #print arg['contents']
        for i in arg:
            if arg[i] is None:
                arg[i]=" "
        self.cur.execute("select count(*) from qq_comments where shuo_shuo_id=\'%s\' and comment_id=\'%s\' "%(arg['shuo_shuo_id'],arg['comment_id']))

        cnt=self.cur.fetchall()[0]['count(*)']

        if cnt==0:
            keys=",".join( str(i) for i in arg)

            #print keys

            values="\",\"".join( arg[i].replace("\""," ") for i in arg)
            values='\"'+values+'\"'
            #print values

            exe="insert into qq_comments(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        elif cnt==1:
            self.cur.execute("select * from qq_comments where shuo_shuo_id=\'%s\' and comment_id=\'%s\' "%(arg['shuo_shuo_id'],arg['comment_id']))
            friend=self.cur.fetchall()
            #print friend[0]
            dic={}
            for i in friend[0]:
                dic[i]=friend[0][i]

            for i in arg:
                dic[i]=arg[i]

            keys=",".join( i for i in dic)

            #print keys

            values="\",\"".join( dic[i].replace("\""," ") for i in dic)
            values='\"'+values+'\"'
            #print values

            self.cur.execute("delete  from qq_comments where shuo_shuo_id=\'%s\' and comment_id=\'%s\' "%(arg['shuo_shuo_id'],arg['comment_id']))
            self.conn.commit()

            exe="insert into qq_comments(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        else:
            print "comment duplicate\n"

    ###############################################################################
    def shuo_shuo_by_profile(self, qq):
        url='http://user.qzone.qq.com/%s'%qq
        url = url + "/1"
        self.webdriver.get(url)
        self.webdriver.implicitly_wait(8)

        self.webdriver.maximize_window()


        frame=self.webdriver.find_elements_by_xpath("//div[@id='app_container']/iframe")
        self.webdriver.switch_to.frame(frame[0])
        self.webdriver.find_elements_by_xpath("//li[@id='feed_tab']/a")[0].click()
        time.sleep(1)
        self.webdriver.switch_to_default_content()
        time.sleep(1)
        for x in range(20):
            self.webdriver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)
            self.webdriver.execute_script("window.scrollTo(0, 0);")
            time.sleep(1)

        self.webdriver.execute_script("window.scrollTo(0, 0);")

        frame=self.webdriver.find_elements_by_xpath("//div[@id='app_container']/iframe")
        self.webdriver.switch_to.frame(frame[0])
        self.webdriver.switch_to.frame("frameFeedList")

        soup = BeautifulSoup(self.webdriver.page_source.encode('utf-8'))

        m_ul = soup.find('ul', attrs={'id': 'host_home_feeds'})

        m_ul = m_ul.findAll("li", attrs={'class': 'f-single f-s-s'})



        add_self=False


        for m_li in m_ul:
            print "$$$$$$$$$$$$$$$$$$$$$$$\n\r"
            sender_qq=qq
            mtime=""
            contents=""
            picture="http://qlogo2.store.qq.com/qzone/%s/%s/100"%(qq,qq)
            comment_num=""
            see_num=""
            zan_num=""
            switch_num=""

            shuo_shuo_id=m_li['id']

            if not add_self:
                try:
                    nick_name=m_li.find("div", attrs={'class': 'f-nick'}).find("a", attrs={'class': 'f-name q_namecard '}).string
                    arg={
                    'parent_qq':qq,
                    'qq':qq,
                    'name':nick_name,
                    'head_picture': "http://qlogo2.store.qq.com/qzone/%s/%s/100" % (qq, qq)
                    }
                    self.add_friend(arg)
                    add_self=True
                except:
                    add_self=False
                    print "add self error 609\n"


            try:
                mtime = m_li.find("div", attrs={'class': 'info-detail'}).find("span", attrs={'class': ' ui-mr8 state'}).string
            except:
                print "time error 447\n"


            try:
                see_num=m_li.find("div", attrs={'class': 'info-detail'}).find("span", attrs={'class': 'state ui-mr10'}).find("a", attrs={'class': 'state qz_feed_plugin'}).contents[1].string
            except:
                see_num="0"



            try:

                b = m_li.find("div", attrs={'class': 'f-info'})
                contents=b.getText()  #contents[0].string
            except:
                print "content null 610\n"

            try:
                p1=m_li.find("p",attrs={"class":"f-detail"})
                comment_num=p1.find("a",attrs={"class":" qz_btn_reply item "}).getText()#contents[1].string

                switch_num=p1.find("a",attrs={"class":"item qz_retweet_btn "}).getText()#contents[1].string

                zan_num=p1.find("a",attrs={"class":"item qz_like_btn_v3"}).getText()#contents[1].string
            except:
                if comment_num is None:
                    comment_num="0"
                if switch_num is None:
                    switch_num="0"
                if zan_num is None:
                    zan_num="0"

            arg={
                'shuo_shuo_id':shuo_shuo_id,
                'sender_qq':sender_qq,
                'time':mtime,
                'contents':contents,
                'comment_num':comment_num,
                'see_num':see_num,
                'zan_num':zan_num,
                'switch_num':switch_num
            }
            self.add_shuo_shuo(arg)





            try:

                like_list=m_li.find("div",attrs={"class":"f-like _likeInfo"}).find("div",attrs={"class":"user-list"})
                if like_list is not None:
                    a=like_list.findAll("a", attrs={'class': 'item'})
                    for img in a:
                        img = img.find("img")
                        nick_name = img["alt"]

                        bei_zan_qq = qq
                        zan_qq = img["link"]
                        zan_qq = re.findall("nameCard_(.*) des", zan_qq)
                        zan_qq = zan_qq[0]

                        zan_time = mtime

                        zan_shuo_shuo_qq = qq
                        zan_shuo_shuo_time = mtime

                        arg = {
                            'shuo_shuo_id':shuo_shuo_id,
                            'zan_qq': zan_qq,
                            'bei_zan_qq': bei_zan_qq

                        }
                        self.add_zan(arg)

                        arg = {
                            'parent_qq': qq,
                            'qq': zan_qq,
                            'name': nick_name,
                            'head_picture': "http://qlogo2.store.qq.com/qzone/%s/%s/100" % (zan_qq, zan_qq)
                        }
                        self.add_friend(arg)

            except:
                print "like list error 651\n"





            ################################

            try:

                comm_list=m_li.find("div",attrs={"class":"comments-list "})

                if comm_list is not None:
                    comm_list=comm_list.find("ul")
                    comm_list=comm_list.contents  #comm_list.findAll("li",attrs={"class":"comments-item bor3"})
                    for li in comm_list:

                        comment_id=li['data-tid']
                        host_qq=qq
                        comment_qq=li["data-uin"]

                        div=li.find("div",attrs={"class":"comments-content"})

                        comm_time=div.find("div",attrs={"class":"comments-op"}).find("span",attrs={"class":" ui-mr10 state"}).string
                        shuo_shuo_qq=qq
                        shuo_shuo_time=mtime
                        contents=li.getText() #div.contents[0].string+div.contents[1].string

                        arg={
                        'shuo_shuo_id':shuo_shuo_id,
                        'comment_id':comment_id,
                        'host_qq':host_qq,
                        'comment_qq':comment_qq,
                        'time':comm_time,
                        'contents':contents
                        }
                        self.add_comment(arg)



                        nick_name=li['data-nick']  #div.find("a",attrs={"class":"c_tx q_namecard"}).string

                        arg={
                        'parent_qq':qq,
                        'qq':comment_qq,
                        'name':nick_name,
                        'head_picture':"http://qlogo2.store.qq.com/qzone/%s/%s/100"%(zan_qq,zan_qq)
                        }
                        self.add_friend(arg)

            except:
                print "comment list error 700\n"




        print "###shuo shuo finish"


##########################################################

    def liu_yan_ban(self, qq):

        url='http://user.qzone.qq.com/%s'%qq
        url = url + "/334"
        self.webdriver.get(url)
        self.webdriver.implicitly_wait(8)
        #self.webdriver.maximize_window()
        self.webdriver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        try:
            self.webdriver.switch_to_frame("tgb")
        except:
            print "switch_to_frame error\n"
            return

        next = True

        while next:
            #self.webdriver.switch_to_default_content()
            #self.webdriver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            #self.webdriver.switch_to_frame("tgb")
            time.sleep(1.2)
            try:
                soup = BeautifulSoup(self.webdriver.page_source.encode('utf-8'))

                m_ul = soup.find("ul", attrs={'id': 'ulCommentList'})

                m_lis = m_ul.contents   #m_ul.findAll("li",attrs={'class': 'bor3 hide_comment_tip'}) #!!!!!!!!!!!!!!!!!




                for m_li in m_lis:
                    print "**********liuyan**********\n\r"

                    try:
                        liuyan_num=m_li['id']
                        head=m_li.find("div", attrs={"class":"info_guest"}).find("p", attrs={"class":"avatar"}).find("a")
                        sender_qq=re.findall("nameCard_(.*)",head["link"])[0]
                        nick=head['title']
                        liuyan_time=m_li.find("p", attrs={"class": "reply_wrap"}).find("span").string
                        contents=m_li.find("td").getText()+"  "+m_li.find("ol").getText()
                    except:
                        print "error 800\n"
                        continue

                    arg={
                    'host_qq':qq,
                    'liuyan_num':liuyan_num,
                    'sender_qq':sender_qq,
                    'time':liuyan_time,
                    'contents':contents
                    }
                    self.add_liuyan(arg)


                    arg={
                    'parent_qq':qq,
                    'qq':sender_qq,
                    'name':nick,
                    'head_picture': "http://qlogo2.store.qq.com/qzone/%s/%s/100" % (sender_qq, sender_qq)
                    }
                    self.add_friend(arg)

            except:
                print "========error 789 : m_lis = m_ul.contents============"


            try:
                self.webdriver.find_element_by_link_text("下一页").click()
            except:
                next = False
                print "###go to the end now\n "



    def get_profile(self ,qq):

        url='http://user.qzone.qq.com/%s'%qq
        url = url + "/1"
        self.webdriver.get(url)
        self.webdriver.implicitly_wait(8)  ###################

        #self.webdriver.maximize_window()

        self.webdriver.execute_script("window.scrollTo(0, 0);")

        try:
            frame=self.webdriver.find_elements_by_xpath("//div[@id='app_container']/iframe")
            self.webdriver.switch_to.frame(frame[0])
            #self.webdriver.switch_to.frame("frameFeedList")

        except:
            print " switch_to_frame error\n"
            return



        try:
            self.webdriver.find_elements_by_xpath("//li[@id='info_tab']/a")[0].click()
            time.sleep(3)
            soup = BeautifulSoup(self.webdriver.page_source.encode('utf-8'))

            info = soup.find('div', attrs={'id': 'info_preview'})

            sex = info.find("div", attrs={'id': 'sex'}).string
            age=info.find("div", attrs={'id': 'age'}).string
            birthday=info.find("div", attrs={'id': 'birthday'}).string
            astro=info.find("div", attrs={'id': 'astro'}).string
            address=info.find("div", attrs={'id': 'live_address'}).getText()
        except:
            print "!!!!!!!!error 865!!!!!!!!!"
            if sex is None:
                sex="none"
            if age is None:
                age="none"
            if birthday is None:
                birthday="none"
            if astro is None:
                astro="none"
            if address is None:
                address="none"




        exe="select * from qq_friends where qq=\"%s\" "%(qq)
        self.cur.execute(exe)
        friend=self.cur.fetchall()
        if friend is None:
            return

        for mfriend in friend:

            dic={}
            for i in mfriend:
                dic[i]=mfriend[i]

            dic['sex']=sex
            dic['age']=age
            dic['birthday']=birthday
            dic['star']=astro
            dic['address']=address

            for i in dic:
                if dic[i] is None:
                    dic[i]="none"

            keys=",".join( i for i in dic)

            #print keys

            values="\",\"".join( dic[i].replace("\""," ") for i in dic)
            values='\"'+values+'\"'
            #print values

            self.cur.execute("delete  from qq_friends where parent_qq=\'%s\' and qq=\'%s\'"%(dic['parent_qq'],dic['qq']))
            self.conn.commit()
            #time.sleep(1)

            exe="insert into qq_friends(%s) values(%s) "%(keys,values)
            #print exe
            self.cur.execute(exe)
            self.conn.commit()

        print "+++++++++get_profile+++++++++"



    def fill_profile(self):

        exe="select distinct qq from qq_friends "
        self.cur.execute(exe)
        friend=self.cur.fetchall()
        for mfriend in friend:
            print mfriend['qq']
            try:
                self.get_profile(mfriend['qq'])
            except:
                continue







    def process(self,host_qq):

        exe="select last_modify from qq_friends where parent_qq=\'%s\' and qq=\'%s\'" %(host_qq,host_qq)
        self.cur.execute(exe)

        try:
            mtime=self.cur.fetchall()[0]['last_modify']
            if mtime is not None:
                diff=int (time.time()-int(mtime) )
                if diff < 1800000:
                    print "need not process\n "
                    try:
                        self.get_profile(host_qq) #catch except
                    except:
                        print "!!!!!get_profile 939 error"
                    return

        except:
            print "no such qq\n"



        self.shuo_shuo_by_profile(host_qq) # no catch except
        self.liu_yan_ban(host_qq) #catch except
        self.get_profile(host_qq) #catch except


    def process_by_csv(self,fileName):
        fi = open(fileName, 'r')
        lines=fi.readlines()
        fi.close()

        fi = open(fileName, 'w')
        fi.close()

        fout=open("tmp.txt","w")
        for line in lines:
            try:
                line=line.split(",")
                host_qq=line[1].strip()
                print host_qq
                #qq=re.findall("(.*)@qq.com",mail)[0]
                #print qq
                have_processed=line[3].strip()

                if have_processed=="0":
                    self.process(host_qq)
                    exe="select  qq  from qq_friends  where  parent_qq=\'%s\' and qq != \'%s\'" %(host_qq,host_qq)
                    qq.cur.execute(exe)
                    friend=qq.cur.fetchall()
                    for mfriend in friend:
                        try:
                            qq.process(mfriend['qq'])
                        except:
                            print "===can not visit==="
                            continue


                    have_processed="1"
            except:
                print "error 972"
                continue

            data=line[0]+","+line[1]+","+line[2]+","+have_processed+"\n"
            fout.write(data)


        fout.close()

        fi2 = open(fileName, 'r')
        lines_fi2=fi2.readlines()
        fi2.close()

        fi2 = open(fileName, 'w')
        fout2=open("tmp.txt","r")
        lines=fout2.readlines()
        fout2.close()
        for line in lines:
            fi2.write(line)
        for line in lines_fi2:
            fi2.write(line)


        fi2.close()



    def dowmload_picture(self,path):

        exe="select distinct head_picture from qq_friends "
        self.cur.execute(exe)
        friend=self.cur.fetchall()
        self.session=requests.Session()


        for mfriend in friend:
            print mfriend['head_picture']
            try:
                self.get_store_pic(mfriend['head_picture'],path)
            except:
                continue

    def get_store_pic(self,url,path):
        qq=re.findall("http://qlogo2.store.qq.com/qzone/(.*)/(.*)/100",url)[0][0]
        print qq
        r=self.session.get(url)
        fout=open("%s%s.jpg"%(path,qq),"wb")
        fout.write(r.content)
        fout.close()


















if __name__ == '__main__':

    qq = QQ(user="1471242852", pwd="CY19930811")
    try:
        mode = int(sys.argv[1])

        if mode == 1:
            print "mode :"
            print mode
            host_qq = sys.argv[2]
            print host_qq

            qq.process(host_qq)

            exe="select  qq  from qq_friends  where  parent_qq=\'%s\' and qq != \'%s\'" %(host_qq,host_qq)

            qq.cur.execute(exe)
            friend=qq.cur.fetchall()
            for mfriend in friend:
                try:
                    qq.process(mfriend['qq'])
                except:
                    print "===can not visit==="
                    continue


        elif mode == 2:
            print "mode :"
            print mode
            qq.dowmload_picture("../public/qq/")
        elif mode == 3:
            print "mode :"
            print mode
            qq.process_by_csv("../req.txt")
        elif mode == 4:
            print "mode :"
            print mode
            host_qq = sys.argv[2]
            print host_qq

            qq.get_profile(host_qq)
        else:
            pass
    except:
        print "error 1034\n"



