
package PeachApi;

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import com.peachapisecurity.api.PeachApiSecurity;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.util.Iterator;
import javax.swing.AbstractAction;
import javax.swing.JOptionPane;

public class TestWithPeachApiMenu extends AbstractAction
{
    private burp.IBurpExtenderCallbacks _callbacks;
    private final PeachApiPreferences _prefs;
    private IContextMenuInvocation _invocation;
    private burp.IExtensionHelpers _helpers;
    private JobWorker _worker;
    private static boolean _enabled = true;

    public TestWithPeachApiMenu(
            burp.IBurpExtenderCallbacks callbacks,
            IContextMenuInvocation invocation,
            PeachApiPreferences prefs)
    {
        super("Test with Peach API Security");
        
        _callbacks = callbacks;
        _prefs = prefs;
        _invocation = invocation;
        _helpers = _callbacks.getHelpers();
        _worker = null;
    }
    
    @Override
    public void actionPerformed(ActionEvent arg0)
    {
        if(!_enabled)
        {
            JOptionPane.showMessageDialog(_prefs.getBurpFrame(), 
                    "A Peach API Security testing job has already been started.\n"+
                        "Only one testing job can be run at a time.\n"+
                        "The current job can be canceled from the Peach API Security -> Test Status "+
                        "tab.\n",
                    "Error", JOptionPane.ERROR_MESSAGE);
            
            return;
        }
        
        disable();
        
        _worker = new JobWorker(_callbacks, _invocation, _prefs);
        _worker.execute();
    }
    
    public synchronized void disable()
    {
        _enabled = false;
        setEnabled(false);
    }
    
    public synchronized void enable()
    {
        _enabled = true;
        setEnabled(true);
    }
}
