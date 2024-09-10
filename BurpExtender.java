package burp;


import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ItemListener;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener,IScannerCheck, IMessageEditorController,IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IMessageEditor requestViewer_proxy;
    private IMessageEditor responseViewer_proxy;
    private final List<LogEntry> log = new ArrayList<LogEntry>();//记录原始流量
    private IHttpRequestResponse currentlyDisplayedItem;
    private IHttpRequestResponse currentlyDisplayedItem_proxy;
    public PrintWriter stdout;
    JTabbedPane tabs;//数据包显示框
    JTabbedPane tabs_1;//数据包的proxy模块开关
    int switchs = 0; //开关 0关 1开
    int conut = 0; //记录条数
    int original_data_len;//记录原始数据包的长度
    int select_row = 0;//选中表格的行数
    Table logTable; //第一个表格框
    String white_URL = "";
    int white_switchs = 0;//白名单开关
    int debug = 0;//调试模式 0关 1开

    JTextArea log_ta;//日志
    JTextField connect_ip;
    JTextArea proxy_decode_data_request;
    JTextArea proxy_decode_data_response;

    //复选框
    //proxy
    JCheckBox p_chkbox1;
    JCheckBox p_chkbox2;
    JCheckBox p_chkbox3;
    //Repeater
    JCheckBox r_chkbox1;
    JCheckBox r_chkbox2;
    //Intruder
    JCheckBox i_chkbox1;
    JCheckBox i_chkbox2;




    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        //输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello xia Jie!");
        this.stdout.println("你好 欢迎使用 瞎解!");
        this.stdout.println("version:1.0");



        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("xia Jie V1.0");

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {

                // main split pane
                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                //表格
                logTable = new Table(BurpExtender.this);
                logTable.getColumnModel().getColumn(3).setPreferredWidth(500);
                JScrollPane scrollPane = new JScrollPane(logTable); //给列表添加滚动条

                JPanel jp=new JPanel();
                jp.setLayout(new GridLayout(1, 1));
                jp.add(scrollPane);    //将表格加到面板

                //侧边复选框
                JPanel jps=new JPanel();
                jps.setLayout(new GridLayout(11, 1)); //六行一列
                JLabel jls=new JLabel("插件名：瞎解 author：算命縖子");    //创建一个标签
                JLabel jls_1=new JLabel("奇安信-深圳安服专用");    //创建一个标签
                JLabel jls_2=new JLabel("版本：xia Jie V1.0");    //创建一个标签
                JLabel jls_3=new JLabel("感谢名单：Moonlit");    //创建一个标签

                JCheckBox chkbox1=new JCheckBox("启动插件");    //创建指定文本和状态的复选框
                connect_ip = new JTextField("127.0.0.1:23002");//白名单文本框
                JCheckBox chkbox2=new JCheckBox("启动调试模式(抓取最终的数据包)");    //创建指定文本和状态的复选框
                JLabel jls_5=new JLabel("如果需要多个域名加白请用,隔开");    //创建一个标签
                JTextField textField = new JTextField("填写白名单域名，强烈建议启动");//白名单文本框
                JButton btn1=new JButton("清空列表与日志");    //创建JButton对象
                JButton btn3=new JButton("启动白名单");    //处理白名单


                JPanel jps_2=new JPanel();
                //proxy模块
                JLabel p_lb=new JLabel("proxy:");    //创建一个标签
                JLabel p_lb_1=new JLabel("加密会修改原始数据包，解密不会修改原始数据包");    //创建一个标签
                p_chkbox1=new JCheckBox("加密proxy请求包流量");    //创建指定文本和状态的复选框
                p_chkbox2=new JCheckBox("解密proxy请求包流量");    //创建指定文本和状态的复选框
                p_chkbox3=new JCheckBox("解密proxy响应包流量");    //创建指定文本和状态的复选框

                //Repeater模块
                JLabel r_lb=new JLabel("Repeater:");    //创建一个标签
                JLabel r_lb_2=new JLabel("解密请求包请到Repeater界面右键解密");    //创建一个标签
                r_chkbox1=new JCheckBox("加密Repeater请求包流量");    //创建指定文本和状态的复选框
                r_chkbox2=new JCheckBox("解密Repeater响应包流量");    //创建指定文本和状态的复选框

                //Intruder模块
                JLabel i_lb=new JLabel("Intruder:");    //创建一个标签
                i_chkbox1=new JCheckBox("加密Intruder请求包流量");    //创建指定文本和状态的复选框
                i_chkbox2=new JCheckBox("解密Intruder响应包流量");    //创建指定文本和状态的复选框、



                //指定面板的布局为GridLayout，1行1列，间隙为0
                jps_2.setLayout(new GridLayout(16,1,0,0));
                jps_2.add(p_lb);
                jps_2.add(p_lb_1);
                jps_2.add(p_chkbox1);
                jps_2.add(p_chkbox2);
                jps_2.add(p_chkbox3);
                jps_2.add(r_lb);
                jps_2.add(r_lb_2);
                jps_2.add(r_chkbox1);
                jps_2.add(r_chkbox2);
                jps_2.add(i_lb);
                jps_2.add(i_chkbox1);
                jps_2.add(i_chkbox2);


                //添加复选框监听事件 开关
                chkbox1.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox1.isSelected()){
                            switchs = 1;
                            connect_ip.setEditable(false);
                            connect_ip.setForeground(Color.GRAY);
                        }else {
                            switchs = 0;
                            connect_ip.setEditable(true);
                            connect_ip.setForeground(Color.BLACK);
                        }
                    }
                });
                //添加复选框监听事件 调试模式
                chkbox2.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if(chkbox2.isSelected()){
                            debug = 1;
                        }else {
                            debug = 0;
                        }

                    }
                });

                btn1.addActionListener(new ActionListener() {//清空列表
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        log.clear();
                        log_ta.setText("");//清除log的内容
                        conut = 0;
                        fireTableRowsInserted(log.size(), log.size());//刷新列表中的展示
                    }
                });
                btn3.addActionListener(new ActionListener() {//白名单
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if(btn3.getText().equals("启动白名单")){
                            btn3.setText("关闭白名单");
                            white_URL = textField.getText();
                            white_switchs = 1;
                            textField.setEditable(false);
                            textField.setForeground(Color.GRAY);//设置组件的背景色
                        }else {
                            btn3.setText("启动白名单");
                            white_switchs = 0;
                            textField.setEditable(true);
                            textField.setForeground(Color.BLACK);
                        }
                    }
                });


                jps.add(jls);
                jps.add(jls_1);
                jps.add(jls_2);
                jps.add(jls_3);
                jps.add(chkbox1);
                jps.add(connect_ip);
                jps.add(chkbox2);
                jps.add(btn1);
                jps.add(jls_5);
                jps.add(textField);
                jps.add(btn3);

                // tabs with request/response viewers
                tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                requestViewer_proxy = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer_proxy = callbacks.createMessageEditor(BurpExtender.this, false);

                //日志
                JPanel log_jp=new JPanel();
                log_jp.setLayout(new GridLayout(1, 1)); //一行一列
                log_ta=new JTextArea("");
                log_ta.setForeground(Color.BLACK);    //设置组件的背景色
                log_ta.setFont(new Font("楷体",Font.BOLD,16));    //修改字体样式
                log_ta.setEditable(false);//不可编辑状态
                JScrollPane jsp=new JScrollPane(log_ta);    //将文本域放入滚动窗口
                log_jp.add(jsp);    //将JScrollPane添加到JPanel容器中

                //数据包
                JSplitPane d_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);//原始数据
                d_jp.setDividerLocation(500);//左右两边的距离
                d_jp.setLeftComponent(requestViewer.getComponent());//添加在左面
                d_jp.setRightComponent(responseViewer.getComponent());//添加在右面

                //proxy解密数据包
                JSplitPane j_jp = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);//原始数据
                j_jp.setDividerLocation(500);//左右两边的距离
                proxy_decode_data_request = new JTextArea("");
                proxy_decode_data_request.setEditable(false);//不可编辑状态
                proxy_decode_data_request.setLineWrap(true);//自动换行
                JScrollPane proxy_decode_data_request_sp=new JScrollPane(proxy_decode_data_request);    //将文本域放入滚动窗口
                proxy_decode_data_response = new JTextArea("");
                proxy_decode_data_response.setEditable(false);//不可编辑状态
                proxy_decode_data_response.setLineWrap(true);//自动换行
                JScrollPane proxy_decode_data_response_sp=new JScrollPane(proxy_decode_data_response);    //将文本域放入滚动窗口
                j_jp.setLeftComponent(proxy_decode_data_request_sp);//添加在左面
                j_jp.setRightComponent(proxy_decode_data_response_sp);//添加在右面

                //如果是proxy的流量
                tabs_1 = new JTabbedPane();
                tabs_1.addTab("最终数据包",d_jp);
                tabs_1.addTab("Proxy流量解密后的数据包",j_jp);

                tabs.addTab("日志",log_jp);
                tabs.addTab("数据包",tabs_1);


                //右边
                splitPanes_2.setLeftComponent(jps);//上面
                splitPanes_2.setRightComponent(jps_2);//下面

                //左边
                splitPanes.setLeftComponent(jp);//上面
                splitPanes.setRightComponent(tabs);//下面

                //整体分布
                splitPane.setLeftComponent(splitPanes);//添加在左面
                splitPane.setRightComponent(splitPanes_2);//添加在右面
                splitPane.setDividerLocation(1000);//设置分割的大小

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(jps);
                callbacks.customizeUiComponent(jp);
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerScannerCheck(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);

            }
        });
    }


    @Override
    public String getTabCaption()
    {
        return "xia Jie";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

        if(switchs == 1){//插件开关
            if(toolFlag == 4 || toolFlag==32 || toolFlag ==64){//监听Proxy/Intruder/Repeater
                // only process responses
                if (!messageIsRequest)
                {//响应包
                    if((i_chkbox2.isSelected() && toolFlag ==32) || (r_chkbox2.isSelected() && toolFlag ==64)){
                        //Intruder/Repeater 解密-单线程处理
                        BurpExtender.this.response_Vul(messageInfo, toolFlag,false);
                    }

                    //proxy解密
                    if((p_chkbox2.isSelected() && toolFlag==4)||(p_chkbox3.isSelected() && toolFlag==4)) {
                            //Proxy流量多线程处理
                            Thread thread = new Thread(new Runnable() {
                                public void run() {
                                    try {
                                        BurpExtender.this.response_Vul(messageInfo,toolFlag,true);
                                    } catch (Exception ex) {
                                        ex.printStackTrace();
                                        BurpExtender.this.stdout.println(ex);
                                    }
                                }
                            });
                            thread.start();
                    }

                    //开启调试模式，proxy、request、intruder 加密
                    if(debug == 1) {
                        if ((p_chkbox1.isSelected() && !p_chkbox2.isSelected() && !p_chkbox3.isSelected() && toolFlag==4) || (r_chkbox1.isSelected() && !r_chkbox2.isSelected() && toolFlag==64) || (i_chkbox1.isSelected() && !i_chkbox2.isSelected() && toolFlag==32)) {
                            if(white_switchs_boolean(messageInfo,toolFlag)) {//白名单处理
                                conut += 1;
                                int id = conut;
                                log.add(new LogEntry(id, helpers.analyzeRequest(messageInfo).getMethod(), callbacks.saveBuffersToTempFiles(messageInfo), "", "", String.valueOf(helpers.analyzeRequest(messageInfo).getUrl()), messageInfo.getResponse().length - helpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset(), toolFlag));

                                //刷新表格
                                BurpExtender.this.fireTableDataChanged();
                                BurpExtender.this.logTable.setRowSelectionInterval(BurpExtender.this.select_row, BurpExtender.this.select_row);
                            }
                        }
                    }


                }else {//请求包
                    if((p_chkbox1.isSelected() && toolFlag ==4) || (i_chkbox1.isSelected() && toolFlag==32) || (r_chkbox1.isSelected() && toolFlag==64)){
                        BurpExtender.this.request_Vul(messageInfo,toolFlag);
                    }

                }
            }

        }

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }


    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        //右键发送按钮功能

        List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>();
        if(invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER || invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_PROXY){
            //父级菜单
            IHttpRequestResponse[] responses = invocation.getSelectedMessages();
            JMenuItem jMenu_decode = new JMenuItem("Send to xia Jie decode");
            JMenuItem jMenu_encode = new JMenuItem("Send to xia Jie encode");

            jMenu_decode.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if(switchs == 1) {
                        //不应在Swing事件调度线程中发出HTTP请求，所以需要创建一个Runnable并在 run() 方法中完成工作，后调用 new Thread(runnable).start() 来启动线程
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    data_return encode_data = BurpExtender.this.xj_decode(responses[0],true);

                                    byte[] body = encode_data.body.getBytes();
                                    byte[] newRequest = helpers.buildHttpMessage(encode_data.header,body);
                                    responses[0].setRequest(newRequest);//设置最终新的请求包

                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }else {
                        BurpExtender.this.stdout.println("插件xia Jie关闭状态！");
                    }

                }
            });

            jMenu_encode.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    if(switchs == 1) {
                        //不应在Swing事件调度线程中发出HTTP请求，所以需要创建一个Runnable并在 run() 方法中完成工作，后调用 new Thread(runnable).start() 来启动线程
                        Thread thread = new Thread(new Runnable() {
                            public void run() {
                                try {
                                    data_return encode_data = BurpExtender.this.xj_encode(responses[0]);

                                    byte[] body = encode_data.body.getBytes();
                                    byte[] newRequest = helpers.buildHttpMessage(encode_data.header,body);
                                    responses[0].setRequest(newRequest);//设置最终新的请求包

                                } catch (Exception ex) {
                                    ex.printStackTrace();
                                    BurpExtender.this.stdout.println(ex);
                                }
                            }
                        });
                        thread.start();
                    }else {
                        BurpExtender.this.stdout.println("插件xia Jie关闭状态！");
                    }

                }
            });
            listMenuItems.add(jMenu_encode);
            listMenuItems.add(jMenu_decode);
        }

        return listMenuItems;
    }

    private  void request_Vul(IHttpRequestResponse baseRequestResponse, int toolFlag){
        //log_ta.insert("请求包\n",0);
        String temp_data = String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl());//url
        String[] temp_data_strarray=temp_data.split("\\?");
        temp_data =temp_data_strarray[0];//获取问号前面的字符串

        //检测白名单
        String[] white_URL_list = white_URL.split(",");
        int white_swith = 0;
        if(white_switchs == 1){
            white_swith = 0;
            for(int i=0;i<white_URL_list.length;i++){
                if(temp_data.contains(white_URL_list[i])){
                    this.stdout.println("白名单URL！"+temp_data);
                    white_swith = 1;
                }
            }
            if(white_swith == 0) {
                this.stdout.println("不是白名单URL！"+temp_data);
                return;
            }
        }
        //用于判断页面后缀是否为静态文件
        if(toolFlag == 4 || toolFlag ==64){//流量是Repeater与proxy来的就对其后缀判断
            String[] static_file = {"jpg","png","gif","css","js","pdf","mp3","mp4","avi","map","svg","ico","svg","woff","woff2"};
            String[] static_file_1 =temp_data.split("\\.");
            String static_file_2 = static_file_1[static_file_1.length-1];//获取最后一个.内容
            for(String i:static_file){
                if(static_file_2.equals(i)){
                    this.stdout.println("当前url为静态文件："+temp_data+"\n");
                    return;
                }
            }
        }

        //加密
        data_return decode_data = xj_encode(baseRequestResponse);
        byte[] body = decode_data.body.getBytes();
        byte[] newRequest = helpers.buildHttpMessage(decode_data.header,body);
        baseRequestResponse.setRequest(newRequest);//设置最终新的请求包

    }

    private void response_Vul(IHttpRequestResponse baseRequestResponse, int toolFlag,boolean isproxy){
        //log_ta.insert("响应包\n",0);
        String temp_data = String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl());//url
        original_data_len = baseRequestResponse.getResponse().length;//原始数据包的长度
        int original_len = original_data_len-helpers.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();//整个数据包长度-响应body开始时的偏移量
        String[] temp_data_strarray=temp_data.split("\\?");
        temp_data =temp_data_strarray[0];//获取问号前面的字符串

        //检测白名单
        String[] white_URL_list = white_URL.split(",");
        int white_swith = 0;
        if(white_switchs == 1){
            white_swith = 0;
            for(int i=0;i<white_URL_list.length;i++){
                if(temp_data.contains(white_URL_list[i])){
                    this.stdout.println("白名单URL！"+temp_data);
                    white_swith = 1;
                }
            }
            if(white_swith == 0) {
                this.stdout.println("不是白名单URL！"+temp_data);
                return;
            }
        }

        //用于判断页面后缀是否为静态文件
        if(toolFlag == 4 || toolFlag ==64){//流量是Repeater与proxy来的就对其后缀判断
            String[] static_file = {"jpg","png","gif","css","js","pdf","mp3","mp4","avi","map","svg","ico","svg","woff","woff2"};
            String[] static_file_1 =temp_data.split("\\.");
            String static_file_2 = static_file_1[static_file_1.length-1];//获取最后一个.内容
            for(String i:static_file){
                if(static_file_2.equals(i)){
                    this.stdout.println("当前url为静态文件："+temp_data+"\n");
                    return;
                }
            }
        }

        String request_data = "";
        String response_data ="";
        if(isproxy){
            if(p_chkbox2.isSelected()){
                //解密proxy请求包
                data_return decode_data = xj_decode(baseRequestResponse,true);
                for(String head:decode_data.header){
                    request_data += head+"\n";
                }
                request_data += "\n"+decode_data.body;

            }
            if(p_chkbox3.isSelected()){
                //解密proxy响应包
                data_return decode_data = xj_decode(baseRequestResponse,false);
                for(String head:decode_data.header){
                    response_data += head+"\n";
                }
                response_data += "\n"+decode_data.body;
            }

        }else {
            //解密
            data_return decode_data = xj_decode(baseRequestResponse,false);
            byte[] bodybyte = decode_data.body.getBytes();
            baseRequestResponse.setResponse(helpers.buildHttpMessage(decode_data.header, bodybyte));
        }


        if(debug == 1){
            conut += 1;
            int id = conut;
            log.add(new LogEntry(id,helpers.analyzeRequest(baseRequestResponse).getMethod(),callbacks.saveBuffersToTempFiles(baseRequestResponse),request_data,response_data,String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl()),original_len,toolFlag));
        }else if (isproxy){
            conut += 1;
            int id = conut;
            log.add(new LogEntry(id,helpers.analyzeRequest(baseRequestResponse).getMethod(),callbacks.saveBuffersToTempFiles(baseRequestResponse),request_data,response_data,String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl()),original_len,toolFlag));
        }


        //刷新第一个列表框
        //BurpExtender.this.fireTableRowsInserted(log.size(), log.size());
        BurpExtender.this.fireTableDataChanged();
        //第一个表格 继续选中之前选中的值
        BurpExtender.this.logTable.setRowSelectionInterval(BurpExtender.this.select_row,BurpExtender.this.select_row);

    }

    public boolean white_switchs_boolean(IHttpRequestResponse baseRequestResponse,int toolFlag){
        String temp_data = String.valueOf(helpers.analyzeRequest(baseRequestResponse).getUrl());//url
        original_data_len = baseRequestResponse.getResponse().length;//原始数据包的长度
        String[] temp_data_strarray=temp_data.split("\\?");
        temp_data =temp_data_strarray[0];//获取问号前面的字符串

        //检测白名单
        String[] white_URL_list = white_URL.split(",");
        int white_swith = 0;
        if(white_switchs == 1){
            white_swith = 0;
            for(int i=0;i<white_URL_list.length;i++){
                if(temp_data.contains(white_URL_list[i])){
                    this.stdout.println("白名单URL！"+temp_data);
                    white_swith = 1;
                }
            }
            if(white_swith == 0) {
                this.stdout.println("不是白名单URL！"+temp_data);
                return false;
            }
        }

        //用于判断页面后缀是否为静态文件
        if(toolFlag == 4 || toolFlag ==64){//流量是Repeater与proxy来的就对其后缀判断
            String[] static_file = {"jpg","png","gif","css","js","pdf","mp3","mp4","avi","map","svg","ico","svg","woff","woff2"};
            String[] static_file_1 =temp_data.split("\\.");
            String static_file_2 = static_file_1[static_file_1.length-1];//获取最后一个.内容
            for(String i:static_file){
                if(static_file_2.equals(i)){
                    this.stdout.println("当前url为静态文件："+temp_data+"\n");
                    return false;
                }
            }
        }
        return true;
    }


    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "#";
            case 1:
                return "来源";
            case 2:
                return "类型";
            case 3:
                return "URL";
            case 4:
                return "响应包长度";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.id;
            case 1:
                return callbacks.getToolName(logEntry.tool);
            case 2:
                return logEntry.Method;
            case 3:
                return logEntry.url;
            case 4:
                return logEntry.original_len;//返回响应包的长度
            default:
                return "";
        }
    }



    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //表格选中设置
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            select_row = row;//记录选中的行数

            //设置点击表格，打开对应数据包的界面
            tabs.setSelectedIndex(1);
            if(logEntry.tool == 4) {
                tabs_1.setEnabledAt(1, true);
            }else {
                tabs_1.setSelectedIndex(0);
                tabs_1.setEnabledAt(1, false);//标签不可用
            }


            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            proxy_decode_data_request.setText(logEntry.request_data);
            proxy_decode_data_response.setText(logEntry.response_data);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }


    private static class LogEntry
    {
        final int id;
        final String Method;
        final IHttpRequestResponsePersisted requestResponse;
        final String request_data;
        final String response_data;
        final String url;
        final int original_len;
        final int tool;


        LogEntry(int id,String Method, IHttpRequestResponsePersisted requestResponse,String request_data,String response_data, String url,int original_len,int tool)
        {
            this.id = id;
            this.Method = Method;
            this.requestResponse = requestResponse;
            this.request_data = request_data;
            this.response_data = response_data;
            this.url = url;
            this.original_len = original_len;
            this.tool = tool;
        }

    }

    //数据处理，用来返回多个值
    final class data_return
    {
        public List<String> header;
        public String body;

        public data_return(List<String> header, String body)
        {
            this.header = header;
            this.body = body;
        }
    }

    public data_return xj_encode(IHttpRequestResponse baseRequestResponse){
        // 使用 `Base64` 编码器对字符串进行编码
        Base64.Encoder encoder = Base64.getEncoder();
        // 解码编码数据
        Base64.Decoder decoder = Base64.getDecoder();

        //加密
        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String headers_data ="";//head头部信息
        for(int i=0;i<headers.size();i++){
            headers_data += headers.get(i)+"\n";
        }
        IRequestInfo analyIRequestInfo = helpers.analyzeRequest(baseRequestResponse);
        int bodyOffset = analyIRequestInfo.getBodyOffset();//通过上面的analyIRequestInfo得到请求数据包体（body）的起始偏移
        String request = helpers.bytesToString(baseRequestResponse.getRequest());

        //headers_data = helpers.base64Encode(headers_data);//base64编码head头部信息
        //String body_data = helpers.base64Encode(request.substring(bodyOffset));//base64编码body信息
        headers_data =encoder.encodeToString(headers_data.getBytes());//base64编码head头部信息
        String body_data = encoder.encodeToString(request.substring(bodyOffset).getBytes());//base64编码body信息
        String post_data = sendPost("http://"+connect_ip.getText()+"/xj_encode","header="+headers_data+"&body="+body_data);//post请求

        //获取处理过后的数据
        //header
        List<String> New_headers= new ArrayList<>();
        String header_pattern="header=(.*?)[^&]*";//正则匹配字母，数字，特殊字符
        Pattern header_Pattern = Pattern.compile(header_pattern);// 创建 Pattern 对象
        Matcher header_matcher = header_Pattern.matcher(post_data);// 现在创建 matcher 对象
        if (header_matcher.find()) {
            //String[] headers_response_data = helpers.bytesToString(helpers.base64Decode(header_matcher.group().substring(7))).split("\n");
            String[] headers_response_data = new String(decoder.decode(header_matcher.group().substring(7))).split("\n");
            for(String head : headers_response_data){
                New_headers.add(head);
            }
        }
        //body
        String body_response_data="";
        String body_pattern="body=(.*?)[^&]*";//正则匹配字母，数字，特殊字符
        Pattern body_Pattern = Pattern.compile(body_pattern);// 创建 Pattern 对象
        Matcher body_matcher = body_Pattern.matcher(post_data);// 现在创建 matcher 对象
        if (body_matcher.find()) {
            //body_response_data = helpers.bytesToString(helpers.base64Decode(body_matcher.group().substring(5)));
            body_response_data = new String(decoder.decode(body_matcher.group().substring(5)));
        }

        return new data_return(New_headers,body_response_data);
    }

    public data_return xj_decode(IHttpRequestResponse baseRequestResponse,boolean messageIsRequest){
        // 使用 `Base64` 编码器对字符串进行编码
        Base64.Encoder encoder = Base64.getEncoder();
        // 解码编码数据
        Base64.Decoder decoder = Base64.getDecoder();

        List<String> New_headers= new ArrayList<>();//header
        String body_response_data="";//body

        if(messageIsRequest){//请求包
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String headers_data ="";//head头部信息
            for(int i=0;i<headers.size();i++){
                headers_data += headers.get(i)+"\n";
            }
            IRequestInfo analyIRequestInfo = helpers.analyzeRequest(baseRequestResponse);
            int bodyOffset = analyIRequestInfo.getBodyOffset();//通过上面的analyIRequestInfo得到请求数据包体（body）的起始偏移
            String request = helpers.bytesToString(baseRequestResponse.getRequest());

            //headers_data = helpers.base64Encode(headers_data);//base64编码head头部信息
            //String body_data = helpers.base64Encode(request.substring(bodyOffset));//base64编码body信息
            headers_data =encoder.encodeToString(headers_data.getBytes());//base64编码head头部信息
            String body_data = encoder.encodeToString(request.substring(bodyOffset).getBytes());//base64编码body信息
            String post_data = sendPost("http://"+connect_ip.getText()+"/xj_decode","header="+headers_data+"&body="+body_data);//post请求

            //获取处理过后的数据
            //header
            String header_pattern="header=(.*?)[^&]*";//正则匹配字母，数字，特殊字符
            Pattern header_Pattern = Pattern.compile(header_pattern);// 创建 Pattern 对象
            Matcher header_matcher = header_Pattern.matcher(post_data);// 现在创建 matcher 对象
            if (header_matcher.find()) {
                //String[] headers_response_data = helpers.bytesToString(helpers.base64Decode(header_matcher.group().substring(7))).split("\n");
                String[] headers_response_data = new String(decoder.decode(header_matcher.group().substring(7))).split("\n");
                for(String head : headers_response_data){
                    New_headers.add(head);
                }
            }

            //body
            String body_pattern="body=(.*?)[^&]*";//正则匹配字母，数字，特殊字符
            Pattern body_Pattern = Pattern.compile(body_pattern);// 创建 Pattern 对象
            Matcher body_matcher = body_Pattern.matcher(post_data);// 现在创建 matcher 对象
            if (body_matcher.find()) {
                //body_response_data = helpers.bytesToString(helpers.base64Decode(body_matcher.group().substring(5)));
                body_response_data = new String(decoder.decode(body_matcher.group().substring(5)));
            }

        }else {//响应包

            IResponseInfo analyzedResponse = helpers.analyzeResponse(baseRequestResponse.getResponse()); //getResponse获得的是字节序列
            List<String> headers = analyzedResponse.getHeaders();
            String headers_data ="";//head头部信息
            for(int i=0;i<headers.size();i++){
                headers_data += headers.get(i)+"\n";
            }

            String resp = new String(baseRequestResponse.getResponse());
            int bodyOffsets = analyzedResponse.getBodyOffset();//响应包是没有参数的概念的，大多需要修改的内容都在body中
            String body = resp.substring(bodyOffsets);

            //headers_data = helpers.base64Encode(headers_data);//base64编码head头部信息
            //String body_data = helpers.base64Encode(body.getBytes());//base64编码body信息
            headers_data =encoder.encodeToString(headers_data.getBytes());//base64编码head头部信息
            String body_data = encoder.encodeToString(body.getBytes());//base64编码body信息
            String post_data = sendPost("http://"+connect_ip.getText()+"/xj_decode","header="+headers_data+"&body="+body_data);//post请求

            //获取处理过后的数据
            //header
            String header_pattern="header=(.*?)[^&]*";//正则匹配
            Pattern header_Pattern = Pattern.compile(header_pattern);// 创建 Pattern 对象
            Matcher header_matcher = header_Pattern.matcher(post_data);// 现在创建 matcher 对象
            if (header_matcher.find()) {
                //String[] headers_response_data = helpers.bytesToString(helpers.base64Decode(header_matcher.group().substring(7))).split("\n");
                String[] headers_response_data = new String(decoder.decode(header_matcher.group().substring(7))).split("\n");
                for(String head : headers_response_data){
                    New_headers.add(head);
                }
            }
            //body
            String body_pattern="body=(.*?)[^&]*";//正则匹配
            Pattern body_Pattern = Pattern.compile(body_pattern);// 创建 Pattern 对象
            Matcher body_matcher = body_Pattern.matcher(post_data);// 现在创建 matcher 对象
            if (body_matcher.find()) {
                //body_response_data = helpers.bytesToString(helpers.base64Decode(body_matcher.group().substring(5)));
                body_response_data = new String(decoder.decode(body_matcher.group().substring(5)));
            }


        }
        return new data_return(New_headers,body_response_data);
    }

    //发送post
    public String sendPost(String url, String param) {
        PrintWriter out = null;
        BufferedReader in = null;
        String result = "";
        try {
            URL realUrl = new URL(url);
            // 打开和URL之间的连接
            URLConnection conn = realUrl.openConnection();
            // 设置通用的请求属性
            conn.setRequestProperty("accept", "*/*");
            conn.setRequestProperty("connection", "Keep-Alive");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("user-agent",
                    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
            // 发送POST请求必须设置如下两行
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setConnectTimeout(3000);
            // 获取URLConnection对象对应的输出流
            out = new PrintWriter(conn.getOutputStream());
            // 发送请求参数
            out.print(param);
            // flush输出流的缓冲
            out.flush();
            // 定义BufferedReader输入流来读取URL的响应
            in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                result += line;
            }
        } catch (Exception e) {
            BurpExtender.this.log_ta.insert("发送 POST 请求出现异常！,请确认接口是否正常。\n",0);
            System.out.println("发送 POST 请求出现异常！"+e);
            e.printStackTrace();
        }
        //使用finally块来关闭输出流、输入流
        finally{
            try{
                if(out!=null){
                    out.close();
                }
                if(in!=null){
                    in.close();
                }
            }
            catch(IOException ex){
                ex.printStackTrace();
            }
        }
        return result;
    }



}
