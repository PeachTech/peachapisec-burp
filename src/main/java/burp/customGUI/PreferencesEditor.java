/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.customGUI;

import PeachApi.PeachApiPreferences;
import burp.ITab;
import com.peachapisecurity.api.Job;
import com.peachapisecurity.api.PeachApiSecurity;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 *
 * @author mike
 */
public class PreferencesEditor extends javax.swing.JPanel {

    private PeachApiPreferences _prefs;

    /**
     * Creates new form PreferenceEditor
     */
    public PreferencesEditor(PeachApiPreferences prefs) {
        _prefs = prefs;
        initComponents();
        
        jTextFieldPeachApiUrl.setText(_prefs.getApiUrl());
        jTextFieldPeachApiToken.setText(_prefs.getApiToken());
        jTextFieldProject.setText(_prefs.getProject());
        jTextFieldProfile.setText(_prefs.getProfile());
        
        setComponentsActions();
    }
    
    private void setComponentsActions()
    {
        jTextFieldPeachApiUrl.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
              update();
            }
            public void removeUpdate(DocumentEvent e) {
              update();
            }
            public void insertUpdate(DocumentEvent e) {
              update();
            }
            public void update() {
                _prefs.setApiUrl(jTextFieldPeachApiUrl.getText());
            }
        });
        
        jTextFieldPeachApiToken.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
              update();
            }
            public void removeUpdate(DocumentEvent e) {
              update();
            }
            public void insertUpdate(DocumentEvent e) {
              update();
            }
            public void update() {
                _prefs.setApiToken(jTextFieldPeachApiToken.getText());
            }
        });
        
        jTextFieldProject.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
              update();
            }
            public void removeUpdate(DocumentEvent e) {
              update();
            }
            public void insertUpdate(DocumentEvent e) {
              update();
            }
            public void update() {
                _prefs.setProject(jTextFieldProject.getText());
            }
        });
        
        jTextFieldProfile.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
              update();
            }
            public void removeUpdate(DocumentEvent e) {
              update();
            }
            public void insertUpdate(DocumentEvent e) {
              update();
            }
            public void update() {
                _prefs.setProfile(jTextFieldProfile.getText());
            }
        });
        
        jButtonTest.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent arg0)
            {
                _testWorker = new TestWorker(
                        _prefs.getApiUrl(), 
                        _prefs.getApiToken(), 
                        jLabelStatus);
                
                _testWorker.execute();
            }
        });
        
        buttonStopJobs.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent arg0)
            {
                int ret = JOptionPane.showConfirmDialog(_prefs.getBurpFrame(), 
                    "This will stop all running jobs regardless if who started them.",
                    "Warning", JOptionPane.OK_CANCEL_OPTION);
                
                if(ret != JOptionPane.OK_OPTION)
                    return;

                new SwingWorker<Void, Void>()
                {
                    @Override
                    public Void doInBackground()
                    {
                        labelStopStatus.setText("Stopping all jobs...");
                        
                        PeachApiSecurity apiSec = new PeachApiSecurity(
                            _prefs.getApiUrl(), "Token " + _prefs.getApiToken(), "", "");

                        try
                        {
                            apiSec.stopAllJobs();
                            
                            labelStopStatus.setText("All jobs stopped.");
                        }
                        catch(Exception e)
                        {
                            labelStopStatus.setText("Error: "+e.getMessage());
                        }
                        
                        return null;
                    }
                }.execute();  
            }
        });
    }

    private TestWorker _testWorker = null;

    private class TestWorker extends SwingWorker<Void, Void>
    {
        JLabel _status;
        String _apiUrl;
        String _apiToken;

        public TestWorker(String apiUrl, String apiToken, JLabel status)
        {
            super();

            _apiUrl = apiUrl;
            _apiToken = apiToken;
            _status = status;
        }

        @Override
        public Void doInBackground()
        {
            try
            {
                _status.setText("Testing...");
                
                PeachApiSecurity apiSec = new PeachApiSecurity(
                    _prefs.getApiUrl(), "Token " + _prefs.getApiToken(), "", "");

                try
                {
                    Job[] jobs = apiSec.getJobs();
                    _status.setText("Connection test success");
                }
                catch(Exception e)
                {
                    _status.setText("Error: "+e.getMessage());
                }
            }
            catch(Exception ex)
            {
                _status.setText("Error: "+ex.getMessage());
            }

            return null;
        }

        @Override
        public void done() {
        }
    }


    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jTextFieldPeachApiUrl = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jTextFieldPeachApiToken = new javax.swing.JTextField();
        jButtonTest = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jTextFieldProject = new javax.swing.JTextField();
        jTextFieldProfile = new javax.swing.JTextField();
        jLabelStatus = new javax.swing.JLabel();
        buttonStopJobs = new javax.swing.JButton();
        labelStopStatus = new javax.swing.JLabel();

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        jLabel1.setText("Peach API Security Settings");

        jLabel2.setText("Peach API URL");

        jTextFieldPeachApiUrl.setToolTipText("");

        jLabel3.setText("Peach API Token");

        jButtonTest.setText("Test Connection");

        jLabel4.setText("Project Name:");

        jLabel5.setText("Project Profile:");

        jLabelStatus.setText("  ");

        buttonStopJobs.setText("Stop All Jobs");

        labelStopStatus.setText("   ");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jLabel1)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButtonTest)
                        .addGap(18, 18, 18)
                        .addComponent(jLabelStatus, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel4)
                        .addGap(18, 18, 18)
                        .addComponent(jTextFieldProject))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel5)
                        .addGap(18, 18, 18)
                        .addComponent(jTextFieldProfile))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(jLabel2))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jTextFieldPeachApiToken, javax.swing.GroupLayout.PREFERRED_SIZE, 220, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jTextFieldPeachApiUrl)))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(buttonStopJobs)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(labelStopStatus, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap(79, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(16, 16, 16)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jTextFieldPeachApiUrl, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jTextFieldPeachApiToken, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonTest)
                    .addComponent(jLabelStatus))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextFieldProject, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.Alignment.TRAILING))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(jTextFieldProfile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(buttonStopJobs)
                    .addComponent(labelStopStatus))
                .addContainerGap(61, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonStopJobs;
    private javax.swing.JButton jButtonTest;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabelStatus;
    public javax.swing.JTextField jTextFieldPeachApiToken;
    public javax.swing.JTextField jTextFieldPeachApiUrl;
    public javax.swing.JTextField jTextFieldProfile;
    public javax.swing.JTextField jTextFieldProject;
    public javax.swing.JLabel labelStopStatus;
    // End of variables declaration//GEN-END:variables
}
