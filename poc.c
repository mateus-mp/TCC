#include <sys/inotify.h>
#include <gtk/gtk.h>
#include <unistd.h>
#include <stdio.h>

#define EVENT_SIZE    (sizeof(struct inotify_event))
#define BUFFER_LEN    (32 * (EVENT_SIZE + 16))

void *show_warning() {
  gtk_init(NULL, NULL);
  GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_skip_taskbar_hint(GTK_WINDOW(window), TRUE);
  GtkWidget *dialog = gtk_message_dialog_new(
    GTK_WINDOW(window),
    GTK_DIALOG_DESTROY_WITH_PARENT,
    GTK_MESSAGE_WARNING,
    GTK_BUTTONS_OK,
    "File accessed");
  gtk_message_dialog_format_secondary_text(
    (GtkMessageDialog *) dialog,
    "OK to continue");
  gtk_window_set_title(GTK_WINDOW(dialog), "Warning");
  g_signal_connect_swapped(dialog,
    "response",
    G_CALLBACK(gtk_widget_destroy),
    window);
  g_signal_connect(window,
    "destroy",
    G_CALLBACK(gtk_main_quit), 
    NULL);
  gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER_ALWAYS);
  gtk_widget_show(window);
  gtk_widget_show(dialog);
  gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
  gtk_widget_hide(window);
  gtk_main();
}

int main(int argc, char **argv) {
  int fd, wd, length, i;
  char buffer[BUFFER_LEN];
  struct inotify_event *event;
  fd_set watch_set;
  
  fd = inotify_init();
  if (fd < 0) {
    perror("inotify_init");
  }
  
  // check if dir exists
  // watch the entire system tree
  wd = inotify_add_watch(fd, "/home/mateus/teste", IN_ALL_EVENTS);
  if (wd < 0) {
    perror("inotify_add_watch");
  }
  
  FD_ZERO(&watch_set);
  FD_SET(fd, &watch_set);
  
  while (1) {
    select(fd + 1, &watch_set, NULL, NULL, NULL);
    length = read(fd, buffer, BUFFER_LEN);
    i = 0;
    while (i < length) {
      event = (struct inotify_event *) &buffer[i];
      if (event->mask & IN_OPEN) {
        pthread_t thread;
        pthread_create(&thread, NULL, show_warning, NULL);
      }
      i += EVENT_SIZE + event->len;
    }
  }
  inotify_rm_watch(fd, wd);
  close(fd);
  return 0;
}

