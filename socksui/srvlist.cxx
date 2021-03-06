// generated by Fast Light User Interface Designer (fluid) version 1.0300

#include "srvlist.h"

void DownloadFile::cb_confirmBtn_i(Fl_Button*, void*) {
  need_to_terminate = 1;
mainWindow->hide();
}
void DownloadFile::cb_confirmBtn(Fl_Button* o, void* v) {
  ((DownloadFile*)(o->parent()->user_data()))->cb_confirmBtn_i(o,v);
}

DownloadFile::DownloadFile(Fl_Font uifont) {
  { mainWindow = new Fl_Window(350, 60, "Downloading");
    mainWindow->box(FL_PLASTIC_UP_BOX);
    mainWindow->color((Fl_Color)207);
    mainWindow->selection_color(FL_DARK1);
    mainWindow->user_data((void*)(this));
    mainWindow->align(Fl_Align(FL_ALIGN_TOP_LEFT));
    { TopNotic = new Fl_Tile(0, 7, 25, 20, "Download file from server.");
      TopNotic->align(Fl_Align(FL_ALIGN_RIGHT));
      TopNotic->labelfont(uifont);
      TopNotic->end();
    } // Fl_Tile* TopNotic
    { downProgre = new Fl_Progress(25, 25, 250, 25, "0%");
      downProgre->box(FL_PLASTIC_UP_BOX);
      downProgre->maximum(100);
      downProgre->minimum(0);
      downProgre->value(0);
      downProgre->labelfont(uifont);
    } // Fl_Progress* downProgre
    { confirmBtn = new Fl_Button(275, 25, 50, 25, "Abort");
      confirmBtn->box(FL_PLASTIC_UP_BOX);
      confirmBtn->down_box(FL_PLASTIC_DOWN_BOX);
      confirmBtn->color((Fl_Color)94);
      confirmBtn->selection_color((Fl_Color)51);
      confirmBtn->callback((Fl_Callback*)cb_confirmBtn);
      confirmBtn->labelfont(uifont);
    } // Fl_Button* confirmBtn
    mainWindow->labelfont(uifont);
    mainWindow->set_modal();
    mainWindow->clear_border();
    mainWindow->size_range(200, 200);
    mainWindow->end();
  } // Fl_Window* mainWindow
  need_to_terminate = 0;
}

DownloadFile::~DownloadFile() {
  delete confirmBtn;
  delete downProgre;
  delete TopNotic;
  delete mainWindow;
}

void DownloadFile::show_window(int trueOrFalse) {
  if (trueOrFalse)
  	mainWindow->show();
  else
  	mainWindow->hide();
}

void DownloadFile::set_progress(float value, char *labelText) {
  downProgre->value(value);
  if (labelText) {
  	downProgre->label(labelText);
  }
}

void DownloadFile::set_captions(const char *title, const char *notice, const char *button) {
  if (notice)
  	TopNotic->label(notice);
  
  if (button)
  	confirmBtn->label(button);
  
  if (title) {
  	mainWindow->label(title);
  }
}

void DownloadFile::set_position(int x, int y) {
  if ((x = -1) && (y= -1)) {
  	int X = (Fl::w() - mainWindow->w()) / 2;
  	int Y = (Fl::h() - mainWindow->h()) / 2;
  	mainWindow->position(X,Y);
  	return;
  }
  
  mainWindow->position(x, y);
  return;
}

void SelectServer::cb_confirmBtn1_i(Fl_Return_Button*, void*) {
  mainWindow->hide();
}
void SelectServer::cb_confirmBtn1(Fl_Return_Button* o, void* v) {
  ((SelectServer*)(o->parent()->user_data()))->cb_confirmBtn1_i(o,v);
}

void SelectServer::cb_skipBtn_i(Fl_Button*, void*) {
  int selectid = -2;
SelectedItem->user_data((void*)selectid);
mainWindow->hide();
}
void SelectServer::cb_skipBtn(Fl_Button* o, void* v) {
  ((SelectServer*)(o->parent()->user_data()))->cb_skipBtn_i(o,v);
}

SelectServer::SelectServer(Fl_Font uifont) {
  { mainWindow = new Fl_Window(295, 290, "Server List");
    mainWindow->box(FL_PLASTIC_UP_BOX);
    mainWindow->color((Fl_Color)207);
    mainWindow->user_data((void*)(this));
    mainWindow->align(Fl_Align(FL_ALIGN_TOP_LEFT));
    mainWindow->hotspot(mainWindow);
    { SelectedItem = new Fl_Tile(0, 215, 25, 25, "Selected item.");
      SelectedItem->align(Fl_Align(FL_ALIGN_RIGHT));
      SelectedItem->labelfont(uifont);
      SelectedItem->end();
    } // Fl_Tile* SelectedItem
    { TopNotic = new Fl_Tile(0, 5, 25, 30, "Please select a socks server:");
      TopNotic->align(Fl_Align(FL_ALIGN_RIGHT));
      TopNotic->labelfont(uifont);
      TopNotic->end();
    } // Fl_Tile* TopNotic
    { ServerBrowser = new Fl_Browser(25, 30, 245, 185);
      ServerBrowser->type(2);
      ServerBrowser->box(FL_PLASTIC_THIN_DOWN_BOX);
      ServerBrowser->color((Fl_Color)207);
      ServerBrowser->labelfont(uifont);
    } // Fl_Browser* ServerBrowser
    { confirmBtn = new Fl_Return_Button(150, 240, 120, 40, "Confirm");
      confirmBtn->box(FL_PLASTIC_UP_BOX);
      confirmBtn->down_box(FL_PLASTIC_DOWN_BOX);
      confirmBtn->color((Fl_Color)127);
      confirmBtn->selection_color((Fl_Color)127);
      confirmBtn->labeltype(FL_EMBOSSED_LABEL);
      confirmBtn->callback((Fl_Callback*)cb_confirmBtn1);
      confirmBtn->window()->hotspot(confirmBtn);
      confirmBtn->labelfont(uifont);
    } // Fl_Return_Button* confirmBtn
    { skipBtn = new Fl_Button(25, 240, 120, 40, "SkipSocks");
      skipBtn->box(FL_PLASTIC_UP_BOX);
      skipBtn->down_box(FL_PLASTIC_DOWN_BOX);
      skipBtn->color((Fl_Color)127);
      skipBtn->selection_color((Fl_Color)127);
      skipBtn->labeltype(FL_EMBOSSED_LABEL);
      skipBtn->callback((Fl_Callback*)cb_skipBtn);
      skipBtn->labelfont(uifont);
    } // Fl_Button* skipBtn
    mainWindow->labelfont(uifont);
    mainWindow->size_range(200, 200);
    mainWindow->end();
  } // Fl_Window* mainWindow
}

SelectServer::~SelectServer() {
  delete skipBtn;
  delete confirmBtn;
  delete ServerBrowser;
  delete TopNotic;
  delete SelectedItem;
  delete mainWindow;
}

void SelectServer::show_window() {
  mainWindow->show();
}

void SelectServer::set_captions(const char *notice,const char *skip,const char *confirm,const char *selectText, int selectid) {
  if (notice)
  	TopNotic->label(notice);
  
  if (skip)
  	skipBtn->label(skip);
  
  if (confirm)
  	confirmBtn->label(confirm);
  
  if (selectText) {
  	SelectedItem->label(selectText);
  	SelectedItem->user_data((void*)selectid);
  }
}

void SelectServer::set_position(int x, int y) {
  if ((x = -1) && (y= -1)) {
  	int X = (Fl::w() - mainWindow->w()) / 2;
  	int Y = (Fl::h() - mainWindow->h()) / 2;
  	mainWindow->position(X,Y);
  	return;
  }
  
  mainWindow->position(x, y);
}

int SelectServer::get_select_result() {
  return (int)SelectedItem->user_data();
}
