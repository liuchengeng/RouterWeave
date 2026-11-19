"""Review missing behavior intervals and export portable data; no model runtime."""
from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .manual_annotations import bounds, export_snapshot, load_timeline, revise_interval


class ManualReviewWindow:
    def __init__(self, parent, run):
        self.run = Path(run).resolve()
        self.start, self.end, self.manifest = bounds(self.run)
        self.iot = bool(self.manifest.get('manual_protocol'))
        self.rows = load_timeline(self.run)
        self.root = tk.Toplevel(parent)
        self.root.title('Screen Time · 补标与导出')
        self.root.geometry('1100x700')
        self.root.minsize(950, 620)
        self.busy = False
        self.selected = None
        self.messages = queue.Queue()
        self.result_dir = None
        body = ttk.Frame(self.root, padding=24)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text=self.run.name, font=('Microsoft YaHei UI', 17, 'bold')).pack(anchor='w')
        self.status = tk.StringVar()
        ttk.Label(body, textvariable=self.status, wraplength=1010).pack(anchor='w', pady=12)
        table_box = ttk.Frame(body)
        table_box.pack(fill='both', expand=True)
        self.table = ttk.Treeview(table_box, columns=('start','end','label','app','status'), show='headings', height=8)
        for key,title,width in [('start','开始',180),('end','结束',180),('label','行为',180),('app','App',160),('status','标签状态',130)]:
            self.table.heading(key,text=title)
            self.table.column(key,width=width)
        self.table.pack(side='left',fill='both',expand=True)
        scroll = ttk.Scrollbar(table_box,command=self.table.yview)
        scroll.pack(side='right',fill='y')
        self.table.configure(yscrollcommand=scroll.set)
        self.table.bind('<<TreeviewSelect>>',self.select_row)
        form = ttk.Frame(body)
        form.pack(fill='x',pady=18)
        from .manual_ui import LABELS
        self.a,self.b,self.label,self.app,self.reason = (tk.StringVar() for _ in range(5))
        self.exclude = tk.BooleanVar(value=False)
        self.controls=[]
        for i,(title,variable) in enumerate([('开始偏移（秒）',self.a),('结束偏移（秒）',self.b),('任务标签',self.label),('App（可选）',self.app)]):
            ttk.Label(form,text=title).grid(row=0,column=i,sticky='w')
            field = (ttk.Combobox(form,textvariable=variable,values=LABELS,width=20) if variable==self.label
                     else ttk.Entry(form,textvariable=variable,width=18))
            field.grid(row=1,column=i,sticky='ew',padx=(0,10),pady=(6,14))
            form.columnconfigure(i,weight=1)
            self.controls.append(field)
        ttk.Label(form,text='补标／修订依据').grid(row=2,column=0,sticky='w')
        reason=ttk.Entry(form,textvariable=self.reason)
        reason.grid(row=3,column=0,columnspan=3,sticky='ew',padx=(0,10),pady=6)
        exclude=ttk.Checkbutton(form,text='无法确定，明确排除',variable=self.exclude)
        exclude.grid(row=2,column=3,sticky='w')
        self.save_button=ttk.Button(form,text='保存补标／修订',command=self.save_review)
        self.save_button.grid(row=3,column=3,sticky='ew')
        self.controls.extend([reason,exclude,self.save_button])
        if self.iot:
            form.pack_forget()
            self.table.heading('start', text='人工打点时间')
            self.table.heading('end', text='后窗截止')
            self.table.heading('app', text='前窗 / 后窗')
        ttk.Label(body,text=('点事件保留原始人工时间；前后窗口不完整的事件会保留并排除。原始流量持续保存。' if self.iot else
                            '无任务时段自动排除，无需补标。仅需修正误标或遗漏的任务；偏移以本轮开始为 0 秒。'),
                  wraplength=1010).pack(anchor='w')
        actions=ttk.Frame(body)
        actions.pack(fill='x',pady=(20,0))
        self.export_button=ttk.Button(actions,text='检查并导出数据',command=self.export)
        self.export_button.pack(side='right')
        self.open_button=ttk.Button(actions,text='打开导出目录',command=self.open_result,state='disabled')
        self.open_button.pack(side='right',padx=10)
        self.controls.append(self.export_button)
        self.root.protocol('WM_DELETE_WINDOW',self.close)
        self.refresh()
        self.root.after(150,self.tick)

    def refresh(self):
        self.rows=load_timeline(self.run)
        self.table.delete(*self.table.get_children())
        if self.iot:
            from .manual_ground_truth import event_windows, read_events
            points = event_windows(read_events(self.run), self.manifest)
            for i, point in enumerate(points):
                local = lambda key: datetime.fromtimestamp(point[key]).strftime('%H:%M:%S.%f')[:-3]
                self.table.insert('', 'end', iid=str(i), values=(local('pc_event_epoch'), local('pc_end_epoch'),
                    point['label'], f"{point['pre_seconds']}s / {point['post_seconds']}s",
                    '完整' if point['input_eligible'] else '窗口不完整'))
            self.status.set(f"人工事件 {len(points)} 个 · 完整窗口 {sum(p['input_eligible'] for p in points)} 个；传感器状态未经自动验证。"
                            if self.manifest['manual_protocol']['mode'] == 'event_markers' else
                            f"日常流量连续观察 {self.end-self.start:.1f} 秒，未生成状态标签。")
            return
        names=dict(pending='待补标',recorded='按钮已标记',confirmed='已补标／修订',excluded='已排除')
        for i,row in enumerate(self.rows):
            local=lambda key:datetime.fromtimestamp(row[key]).strftime('%H:%M:%S.%f')[:-3]
            self.table.insert('','end',iid=str(i),values=(local('pc_start_epoch'),local('pc_end_epoch'),
                              '无任务' if row['label']=='no_task' else row['label'],row['app'],names[row['review_status']]))
        pending=sum(r['pc_end_epoch']-r['pc_start_epoch'] for r in self.rows if r['review_status']=='pending')
        excluded=sum(r['pc_end_epoch']-r['pc_start_epoch'] for r in self.rows if r['review_status']=='excluded')
        task_seconds=sum(r['pc_end_epoch']-r['pc_start_epoch'] for r in self.rows if r['review_status'] in {'recorded','confirmed'})
        self.status.set(f'任务 {task_seconds:.1f} 秒 · 非输入时段 {excluded:.1f} 秒 · 未确定任务 {pending:.1f} 秒。')

    def select_row(self,_event=None):
        if self.iot or self.busy or not self.table.selection():
            return
        self.selected=self.rows[int(self.table.selection()[0])]
        self.initial_a=f"{self.selected['pc_start_epoch']-self.start:.6f}"
        self.initial_b=f"{self.selected['pc_end_epoch']-self.start:.6f}"
        self.a.set(self.initial_a)
        self.b.set(self.initial_b)
        self.label.set(self.selected['label'])
        self.app.set(self.selected['app'])
        self.reason.set('')
        self.exclude.set(self.selected['review_status']=='excluded')

    def save_review(self):
        if self.iot or self.busy:
            return
        try:
            if not self.selected:
                raise ValueError('请先选择需要补标或修正的时间段')
            a=self.selected['pc_start_epoch'] if self.a.get()==self.initial_a else self.start+float(self.a.get())
            b=self.selected['pc_end_epoch'] if self.b.get()==self.initial_b else self.start+float(self.b.get())
            revise_interval(self.run,start=a,end=b,label=self.label.get(),app=self.app.get(),
                            screen_state=self.selected['screen_state'],reason=self.reason.get(),exclude=self.exclude.get())
            self.selected=None
            self.refresh()
        except Exception as exc:
            messagebox.showerror('标签未保存',str(exc),parent=self.root)

    def new_output(self):
        return self.run.parent.parent/'manual-screen-time-exports'/self.run.name/datetime.now().strftime('%Y%m%d-%H%M%S-%f')

    def export(self):
        if self.busy:
            return
        self.busy=True
        for widget in self.controls:
            widget.configure(state='disabled')
        out=self.new_output()
        self.status.set('正在检查时间、抓包完整性和标签，并复制可独立使用的数据包…')
        def work():
            try:
                value=export_snapshot(self.run,out)
                self.messages.put((out,value,None))
            except Exception as exc:
                self.messages.put((None,None,str(exc)))
        threading.Thread(target=work,daemon=False).start()

    def tick(self):
        try:
            out,value,error=self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy=False
            for widget in self.controls:
                widget.configure(state='normal')
            if error:
                self.status.set('导出未完成：'+error)
            else:
                self.result_dir=out
                self.open_button.configure(state='normal')
                if not value['capture_ready']:
                    result='抓包检查未通过：'+'；'.join(value['errors'])
                elif self.iot:
                    result = f"连续流量与事件文件已导出；完整事件窗口 {sum(p['input_eligible'] for p in value['event_windows'])} 个。"
                elif value['task_data_ready']:
                    result=f"数据检查通过。PCAP 完整连续保留；真值已标记 {value['no_task_seconds']:.1f} 秒无任务时段，input_eligible=False。"
                else:
                    result=f"数据检查通过；待补标 {value['review_seconds']['pending']:.1f} 秒、排除 {value['review_seconds']['excluded']:.1f} 秒，已标记区间可单独使用。"
                self.status.set(result+' 导出目录：'+str(out))
        self.root.after(150,self.tick)

    def open_result(self):
        if self.result_dir:
            os.startfile(self.result_dir)

    def close(self):
        if self.busy:
            self.status.set('正在导出数据，请完成后再关闭。')
        else:
            self.root.destroy()
