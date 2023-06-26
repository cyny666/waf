import tkinter
from tkinter import Button
from tkinter import font
from tkinter import ttk

# 点击按钮后的函数
def add_rules ():
    add=tkinter.Tk()
    add.title("add the rules")
    add.geometry("800x400+400+200")

    add.mainloop()
def remove_rules ():
    remove = tkinter.Tk()
    remove.title("remove the rules")
    remove.geometry("800x400+400+200")
    remove.mainloop()
def modify_rules ():
    modify = tkinter.Tk()
    modify.title("modify the rules")
    modify.geometry("800x400+400+200")
    modify.mainloop()
def check_log ():
    check_log = tkinter.Tk()
    check_log.title("系统日志")
    check_log.geometry("800x400+400+200")

    check_log.mainloop()
# 开始主函数
root=tkinter.Tk()
root.title("set the rules")
# set the size
root.geometry("1000x450+300+200")
# set the buttons
module = font.Font(family='Helvetica', size=12, weight='bold')
modify_rules = Button(root,text = "修改规则" ,command = modify_rules, font=module)
add_rules = Button(root, text = "添加规则" ,command = add_rules, font=module)
remove_rules = Button(root,text = "删除规则" ,font = module,command = remove_rules)
run_projetc = Button(root, text = "开始过滤" ,font = module)
stop_project = Button(root, text= "停止过滤" ,font = module)
output = Button(root,text="导出规则", font = module)
check_log = Button(root, text='查看日志' ,font= module)
# 展示按钮
modify_rules.place(x = 190, y = 20)
add_rules.place(x=20,y=20)
remove_rules.place(x = 360, y = 20)
run_projetc.place(x = 530, y = 20)
stop_project.place(x = 700 , y = 20)
output.place(x = 870, y = 20)
check_log.place(x = 870, y = 400)
# 插入规则表格
columns = ['Number','SADDR','SPORT','DADDR','DPORT','TIME_FLAG','TIME_BEGIN','TIME_END','PROTOCOL']
table = ttk.Treeview(
    master=root, height = 15,columns=columns,show='headings',
)
table.heading(column='Number',text='Number',anchor='w')
table.heading('SADDR',text='SADDR')
table.heading('SPORT', text='SPORT')
table.heading('DADDR',text='DADDR')
table.heading('DPORT', text='DPORT')
table.heading('TIME_FLAG', text='TIME_FLAG')
table.heading('TIME_BEGIN', text='TIME_BEGIN')
table.heading('TIME_END', text='TIME_END')
table.heading('PROTOCOL', text='PROTOCOL')
table.column('Number', width=100 ,minwidth=100,anchor='s')
table.column('SADDR', width=100 ,minwidth=100,anchor='s')
table.column('SPORT', width=100 ,minwidth=100,anchor='s')
table.column('DADDR', width=100 ,minwidth=100,anchor='s')
table.column('DPORT', width=100 ,minwidth=100,anchor='s')
table.column('TIME_FLAG', width=100 ,minwidth=100,anchor='s')
table.column('TIME_BEGIN', width=100 ,minwidth=100,anchor='s')
table.column('TIME_END', width=100 ,minwidth=100,anchor='s')
table.column('PROTOCOL', width=100 ,minwidth=100,anchor='s')
table.place(x=20, y=70)

#show the window
root.mainloop()










