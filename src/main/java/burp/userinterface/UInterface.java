package burp.userinterface;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.util.IHttpServiceImpl;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.LinkedList;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author Joaquin R. Martinez
 */
public class UInterface extends JPanel implements ActionListener {

	private static final long serialVersionUID = 1L;
	private DefaultTableModel requestsModel;
    private IMessageEditor msgeditorRequest, msgeditorResponse;
    private LinkedList<IHttpRequestResponse> requestsList;
    private IExtensionHelpers helpers;
    //private int contRequests;
    private JTable requestsTable;
    private JButton cleanButton;

    public UInterface(IBurpExtenderCallbacks ibec) {
        super(new GridLayout());
        this.helpers = ibec.getHelpers();
        this.requestsList = new LinkedList<>();
        this.cleanButton = new JButton("clear table");
        this.cleanButton.addActionListener(this);
        //contRequests = 1;
        this.requestsModel = new DefaultTableModel(new String[]{"method", "url", "Status"}, 0);
        this.msgeditorRequest = ibec.createMessageEditor(new IMessageEditorController() {
            @Override
            public IHttpService getHttpService() {
                int selectedRow = requestsTable.getSelectedRow();
                if (selectedRow != -1) {
                    IHttpRequestResponse request = requestsList.get(selectedRow);
                    return new IHttpServiceImpl(helpers.analyzeRequest(request).getUrl());
                }
                return null;
            }

            @Override
            public byte[] getRequest() {
                return msgeditorRequest.getMessage();
            }

            @Override
            public byte[] getResponse() {
                return null;
            }
        }, false);
        this.msgeditorResponse = ibec.createMessageEditor(new IMessageEditorController() {
            @Override
            public IHttpService getHttpService() {
                int selectedRow = requestsTable.getSelectedRow();
                if (selectedRow != -1) {
                    IHttpRequestResponse request = requestsList.get(selectedRow);
                    return new IHttpServiceImpl(helpers.analyzeRequest(request).getUrl());
                }
                return null;
            }

            @Override
            public byte[] getRequest() {
                return null;
            }

            @Override
            public byte[] getResponse() {
                return msgeditorResponse.getMessage();
            }
        }, false);

        requestsTable = new JTable();
        requestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestsTable.getSelectionModel().addListSelectionListener((ListSelectionEvent e) -> {
            int selectedRow = requestsTable.getSelectedRow();
            if (selectedRow != -1) {
                IHttpRequestResponse httpReqResU1 = requestsList.get(selectedRow);
                msgeditorRequest.setMessage(httpReqResU1.getRequest(), true);
                msgeditorResponse.setMessage(httpReqResU1.getResponse(), false);
            }
        });
        requestsTable.setModel(this.requestsModel);
        JPanel pnlIzquierdo = new JPanel(new BorderLayout());
        JScrollPane sclTbSuspiciuslRequests = new JScrollPane();
        sclTbSuspiciuslRequests.setViewportView(requestsTable);
        Border brdPnlSuspicius = new TitledBorder(new LineBorder(Color.BLACK), "Suspicious List");
        sclTbSuspiciuslRequests.setBorder(brdPnlSuspicius);
        pnlIzquierdo.add(sclTbSuspiciuslRequests, "Center");

        JPanel pnlClearRequests = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        pnlClearRequests.add(cleanButton);
        pnlIzquierdo.add(pnlClearRequests, "South");
        //crear tab que contiene los del usuario 1 y 2, ademas los del CSRF
        JTabbedPane tab_principal = new JTabbedPane();
        tab_principal.add("Request", this.msgeditorRequest.getComponent());
        tab_principal.add("Response", this.msgeditorResponse.getComponent());

        JSplitPane principal = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        principal.add(pnlIzquierdo);
        principal.add(tab_principal);
        this.add(principal);
        ibec.customizeUiComponent(this);
    }

    public void sendToTable(IHttpRequestResponse original) {
        if (!alreadyExists(original)) {
            this.requestsList.add(original);
            IRequestInfo requestInfo = this.helpers.analyzeRequest(original);
            IResponseInfo responseInfo = this.helpers.analyzeResponse(original.getResponse());
            this.requestsModel.addRow(new String[]{requestInfo.getMethod(), requestInfo.getUrl().toString(),
                String.valueOf(responseInfo.getStatusCode())});
        }
    }

    public boolean alreadyExists(IHttpRequestResponse original) {
        URL url = helpers.analyzeRequest(original).getUrl();
        for (IHttpRequestResponse iHttpRequestResponse : requestsList) {
            URL u = helpers.analyzeRequest(iHttpRequestResponse).getUrl();
            if (u.toString().equals(url.toString())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        this.requestsList.clear();
        this.requestsModel.setRowCount(0);
    }

}
