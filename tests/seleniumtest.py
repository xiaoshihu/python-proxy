# -*- coding: utf-8 -*-

"""
    @author: xiaoshihu
    @file: seleniumtest.py
    @time: 2019/5/23 9:39
    @desc: 
"""
from selenium import webdriver
chromeOptions = webdriver.ChromeOptions()

# 设置代理
chromeOptions.add_argument("--proxy-server=http://127.0.0.1:8080")
# 一定要注意，=两边不能有空格，不能是这样--proxy-server = http://202.20.16.82:10152
browser = webdriver.Chrome(options = chromeOptions)

# 查看本机ip，查看代理是否起作用
browser.get("https://cn.bing.com/?scope=web&FORM=QBRE")
# print(browser.page_source)

# 退出，清除浏览器缓存
# browser.quit()