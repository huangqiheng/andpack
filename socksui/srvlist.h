// generated by Fast Light User Interface Designer (fluid) version 1.0300

#ifndef srvlist_h
#define srvlist_h
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Tile.H>
#include <FL/Fl_Progress.H>
#include <FL/Fl_Button.H>

class DownloadFile {
public:
  int need_to_terminate; 
  char *fromurl; 
  char *tofile; 
  DownloadFile(Fl_Font uifont);
protected:
  Fl_Window *mainWindow;
  Fl_Tile *TopNotic;
  Fl_Progress *downProgre;
  Fl_Button *confirmBtn;
private:
  void cb_confirmBtn_i(Fl_Button*, void*);
  static void cb_confirmBtn(Fl_Button*, void*);
public:
  ~DownloadFile();
  void show_window(int trueOrFalse);
  void set_progress(float value, char *labelText);
  void set_captions(const char *title, const char *notice, const char *button);
  void set_position(int x, int y);
};
#include <FL/Fl_Browser.H>
#include <FL/Fl_Return_Button.H>

class SelectServer {
public:
  void *thread_cond; 
  int need_to_exit; 
  int argc; 
  char **argv; 
  SelectServer(Fl_Font uifont);
protected:
  Fl_Window *mainWindow;
  Fl_Tile *SelectedItem;
  Fl_Tile *TopNotic;
public:
  Fl_Browser *ServerBrowser;
protected:
  Fl_Return_Button *confirmBtn;
private:
  void cb_confirmBtn1_i(Fl_Return_Button*, void*);
  static void cb_confirmBtn1(Fl_Return_Button*, void*);
public:
  Fl_Button *skipBtn;
private:
  void cb_skipBtn_i(Fl_Button*, void*);
  static void cb_skipBtn(Fl_Button*, void*);
public:
  ~SelectServer();
  void show_window();
  void set_captions(const char *notice,const char *skip,const char *confirm,const char *selectText, int selectid);
  void set_position(int x, int y);
  int get_select_result();
};
#endif