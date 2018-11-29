package PeachApi;
import burp.BurpExtender;
import burp.customGUI.PeachApiTab;
import java.awt.Frame;
import java.util.prefs.Preferences;

public class PeachApiPreferences
{
	private Preferences prefs=Preferences.userRoot().node("PeachApi");
        
	private final String appName = "Peach API Security Extension";
	private final String author = "Peach Tech (support@peach.tech)";
	private final String authorLink = "https://peach.tech";
	private final String projectLink = "https://peach.tech";

	private boolean isDebugMode;
        private String _apiUrl;
        private String _apiToken;
        private String _project;
        private String _profile;
        
        private PeachApiTab _apiTab;
        private BurpExtender _root;
        private JobWorker _jobWorker = null;
        private StatusUpdateWorker _statusUpdateWorker = null;
        
        public PeachApiPreferences()
        {
            isDebugMode = prefs.getBoolean("isDebugMode", false);

            _apiUrl = prefs.get("apiUrl", "");
            _apiToken = prefs.get("apiToken", "");
            _project = prefs.get("project", "");
            _profile = prefs.get("profile", "Quick");
            _apiTab = null;
	}
        
        public synchronized Frame getBurpFrame()
        {
            Frame[] frames = Frame.getFrames();
            for(Frame frame : frames)
            {
                if(frame.getTitle().startsWith("Burp Suite"))
                    return frame;
            }
            
            return null;
        }
        
        public synchronized BurpExtender getExtension()
        {
            return _root;
        }
        public synchronized void setExtension(BurpExtender root)
        {
            _root = root;
        }

        public synchronized PeachApiTab getApiTab()
        {
            return _apiTab;
        }
        public synchronized void setApiTab(PeachApiTab apiTab)
        {
            _apiTab = apiTab;
        }

        public synchronized JobWorker getJobWorker()
        {
            return _jobWorker;
        }
        public synchronized void setJobWorker(JobWorker jobWorker)
        {
            _jobWorker = jobWorker;
        }

        public synchronized StatusUpdateWorker getStatusUpdateWorker()
        {
            return _statusUpdateWorker;
        }
        public synchronized void setStatusUpdateWorker(StatusUpdateWorker statusUpdateWorker)
        {
            _statusUpdateWorker = statusUpdateWorker;
        }

	public synchronized String getVersion()
        {
            return BuildConfig.VERSION;
	}

	public synchronized String getProjectLink()
        {
		return projectLink;
	}
	
        public synchronized String getAppInfo()
        {
		return "Name: "+appName + " -Version: " + getVersion() + " -Source: " + projectLink + " -Author: " + author;
	}

	public synchronized boolean isDebugMode()
        {
            return isDebugMode;
	}
	public synchronized void setDebugMode(boolean isDebugMode)
        {
            prefs.putBoolean("isDebugMode", isDebugMode);
            this.isDebugMode = isDebugMode;
	}

	public synchronized String getApiUrl()
        {
            return _apiUrl;
	}
	public synchronized void setApiUrl(String apiUrl)
        {
            prefs.put("apiUrl", apiUrl);
            _apiUrl = apiUrl;
	}

	public synchronized String getApiToken()
        {
            return _apiToken;
	}
	public synchronized void setApiToken(String apiToken)
        {
            prefs.put("apiToken", apiToken);
            _apiToken = apiToken;
	}

	public synchronized String getProject()
        {
            return _project;
	}
	public synchronized void setProject(String project)
        {
            prefs.put("project", project);
            _project = project;
	}

	public synchronized String getProfile()
        {
            return _profile;
	}
	public synchronized void setProfile(String profile)
        {
            prefs.put("profile", profile);
            _profile = profile;
	}
}
